#!/usr/bin/env python3
"""Build a country-balanced subscription after real end-to-end proxy checks.

Each candidate is converted to a Mihomo proxy, then Mihomo's controller API
performs HTTPS requests through that exact proxy.  A node is selected only when
all configured test URLs pass.  Countries keep at most MAX_PER_COUNTRY nodes;
when fewer pass, all passing nodes are kept.
"""

from __future__ import annotations

import base64
import concurrent.futures
import dataclasses
import hashlib
import html
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


OWNER = "sakha1370"
REPO = "OpenRay"
BRANCH = "main"
COUNTRY_API = (
    f"https://api.github.com/repos/{OWNER}/{REPO}/contents/output/country"
    f"?ref={BRANCH}"
)


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(minimum, min(maximum, value))


MAX_PER_COUNTRY = env_int("MAX_PER_COUNTRY", 5, 1, 20)
MAX_CANDIDATES_PER_COUNTRY = env_int(
    "MAX_CANDIDATES_PER_COUNTRY", 40, MAX_PER_COUNTRY, 200
)
CHECK_TIMEOUT_MS = env_int("CHECK_TIMEOUT_MS", 8000, 2000, 30000)
CHECK_WORKERS = env_int("CHECK_WORKERS", 64, 1, 256)
CHECK_BATCH_SIZE = env_int("CHECK_BATCH_SIZE", 8, 1, 50)
DOWNLOAD_WORKERS = env_int("DOWNLOAD_WORKERS", 16, 1, 32)
MIN_TOTAL_WORKING = env_int("MIN_TOTAL_WORKING", 5, 1, 1000)

DEFAULT_TEST_URLS = (
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
)
TEST_URLS = tuple(
    item.strip()
    for item in os.environ.get("CHECK_URLS", ",".join(DEFAULT_TEST_URLS)).split(",")
    if item.strip()
)

SUPPORTED_PREFIXES = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
)

VMESS_CIPHERS = {
    "auto",
    "none",
    "zero",
    "aes-128-gcm",
    "chacha20-poly1305",
}

SS_CIPHERS = {
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "aes-128-ccm",
    "aes-192-ccm",
    "aes-256-ccm",
    "aes-128-gcm-siv",
    "aes-256-gcm-siv",
    "chacha20-ietf",
    "chacha20",
    "xchacha20",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "chacha8-ietf-poly1305",
    "xchacha8-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "lea-128-gcm",
    "lea-192-gcm",
    "lea-256-gcm",
    "rabbit128-poly1305",
    "aegis-128l",
    "aegis-256",
    "aez-384",
    "deoxys-ii-256-128",
    "rc4-md5",
    "none",
}


@dataclasses.dataclass
class Candidate:
    country: str
    uri: str
    name: str
    protocol: str
    endpoint: str
    proxy: dict[str, Any]


def log(message: str) -> None:
    print(message, flush=True)


def github_headers() -> dict[str, str]:
    headers = {
        "User-Agent": "OpenRay-Balanced-Healthcheck/2.0",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def http_get(url: str, timeout: float = 45) -> bytes:
    request = urllib.request.Request(url, headers=github_headers())
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def get_json(url: str) -> Any:
    return json.loads(http_get(url).decode("utf-8"))


def maybe_decode_subscription(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="replace").strip()
    if any(prefix in text for prefix in SUPPORTED_PREFIXES):
        return text

    compact = re.sub(r"\s+", "", text)
    if not compact:
        return ""
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    for altchars in (None, b"-_"):
        try:
            decoded = base64.b64decode(padded, altchars=altchars, validate=False)
            candidate = decoded.decode("utf-8", errors="replace").strip()
            if any(prefix in candidate for prefix in SUPPORTED_PREFIXES):
                return candidate
        except Exception:
            continue
    return text


def b64decode_text(value: str) -> str:
    compact = re.sub(r"\s+", "", urllib.parse.unquote(value))
    compact += "=" * ((4 - len(compact) % 4) % 4)
    for altchars in (b"-_", None):
        try:
            return base64.b64decode(
                compact, altchars=altchars, validate=False
            ).decode("utf-8", errors="strict")
        except Exception:
            continue
    raise ValueError("invalid base64")


def normalized_uri(uri: str) -> str:
    return html.unescape(uri.strip())


def query_values(query: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = defaultdict(list)
    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        result[key.lower()].append(value)
    return result


def qget(values: dict[str, list[str]], *names: str, default: str = "") -> str:
    for name in names:
        items = values.get(name.lower())
        if items:
            return str(items[0])
    return default


def is_true(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def split_list(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = value
    else:
        raw = re.split(r"[,;]", str(value or ""))
    return [str(item).strip() for item in raw if str(item).strip()]


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def split_host_port(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or end + 2 > len(value) or value[end + 1] != ":":
            raise ValueError("invalid IPv6 host:port")
        return value[1:end], int(value[end + 2 :])
    host, port = value.rsplit(":", 1)
    return host.strip(), int(port)


def endpoint_key(server: str, port: int) -> str:
    # Deliberately ignore UUID/password: two credentials on one host:port are
    # not independent servers and should not occupy two country slots.
    return f"{server.strip().casefold()}:{int(port)}"


def apply_tls(
    proxy: dict[str, Any],
    values: dict[str, list[str]],
    *,
    implicit_tls: bool = False,
    sni_key: str = "servername",
) -> bool:
    security = qget(values, "security").lower()
    tls_enabled = implicit_tls or security in {"tls", "reality"}
    if not tls_enabled:
        return True

    if not implicit_tls:
        proxy["tls"] = True

    sni = qget(values, "sni", "servername", "server_name")
    if sni:
        proxy[sni_key] = sni

    alpn = split_list(qget(values, "alpn"))
    if alpn:
        proxy["alpn"] = alpn

    client_fp = qget(values, "fp", "client-fingerprint", "clientfingerprint")
    if client_fp:
        proxy["client-fingerprint"] = client_fp

    insecure = qget(
        values,
        "insecure",
        "allowinsecure",
        "allow_insecure",
        "skip-cert-verify",
    )
    if is_true(insecure):
        proxy["skip-cert-verify"] = True

    if security == "reality":
        public_key = qget(values, "pbk", "public-key", "publickey")
        if not public_key:
            return False
        proxy["reality-opts"] = {
            "public-key": public_key,
            "short-id": qget(values, "sid", "short-id", "shortid"),
            "spider-x": qget(values, "spx", "spiderx", "spider-x"),
        }
    return True


def apply_transport(
    proxy: dict[str, Any],
    values: dict[str, list[str]],
    *,
    protocol: str,
) -> bool:
    network = qget(values, "type", "network", default="tcp").strip().lower()
    path = qget(values, "path", default="/") or "/"
    host = qget(values, "host", "authority")

    if network in {"", "tcp", "raw", "none"}:
        proxy["network"] = "tcp"
        return True

    if network in {"ws", "wss", "httpupgrade"}:
        proxy["network"] = "ws"
        options: dict[str, Any] = {"path": path}
        if host:
            options["headers"] = {"Host": host}
        early_data = qget(values, "ed", "max-early-data")
        if early_data.isdigit():
            options["max-early-data"] = int(early_data)
            header = qget(values, "eh", "early-data-header-name")
            if header:
                options["early-data-header-name"] = header
        if network == "httpupgrade":
            options["v2ray-http-upgrade"] = True
        proxy["ws-opts"] = options
        return True

    if network in {"grpc", "gun"}:
        proxy["network"] = "grpc"
        service = qget(values, "servicename", "service", "path").lstrip("/")
        options = {"grpc-service-name": service}
        authority = qget(values, "authority", "host")
        if authority:
            options["grpc-authority"] = authority
        proxy["grpc-opts"] = options
        return True

    if network in {"http", "h2"}:
        proxy["network"] = network
        if network == "http":
            options = {"path": [path]}
            if host:
                options["headers"] = {"Host": [host]}
            proxy["http-opts"] = options
        else:
            options = {"path": path}
            if host:
                options["host"] = [host]
            proxy["h2-opts"] = options
        return True

    if network in {"xhttp", "splithttp"} and protocol == "vless":
        proxy["network"] = "xhttp"
        options = {"path": path}
        if host:
            options["host"] = host
        mode = qget(values, "mode")
        if mode:
            options["mode"] = mode

        extra = qget(values, "extra")
        if extra:
            try:
                extra_obj = json.loads(extra)
            except Exception:
                extra_obj = {}
            mapping = {
                "noGRPCHeader": "no-grpc-header",
                "xPaddingBytes": "x-padding-bytes",
                "xPaddingObfsMode": "x-padding-obfs-mode",
                "xPaddingKey": "x-padding-key",
                "xPaddingHeader": "x-padding-header",
                "xPaddingPlacement": "x-padding-placement",
                "xPaddingMethod": "x-padding-method",
                "uplinkHTTPMethod": "uplink-http-method",
                "scMaxEachPostBytes": "sc-max-each-post-bytes",
                "scMinPostsIntervalMs": "sc-min-posts-interval-ms",
            }
            for source, target in mapping.items():
                if source in extra_obj:
                    options[target] = extra_obj[source]
        proxy["xhttp-opts"] = options
        return True

    # Never test a different transport than the one in the share link.
    return False


def parse_vless(uri: str, name: str) -> dict[str, Any] | None:
    try:
        parsed = urllib.parse.urlsplit(uri)
        server = parsed.hostname or ""
        port = parsed.port or 0
        uuid = urllib.parse.unquote(parsed.username or "")
        if not server or not port or not uuid:
            return None
        values = query_values(parsed.query)
        proxy: dict[str, Any] = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "udp": True,
        }
        flow = qget(values, "flow")
        if flow:
            proxy["flow"] = flow
        encryption = qget(values, "encryption")
        if encryption and encryption.lower() != "none":
            proxy["encryption"] = encryption
        packet_encoding = qget(values, "packetencoding", "packet-encoding")
        if packet_encoding:
            proxy["packet-encoding"] = packet_encoding
        if not apply_tls(proxy, values):
            return None
        if not apply_transport(proxy, values, protocol="vless"):
            return None
        return proxy
    except Exception:
        return None


def parse_vmess(uri: str, name: str) -> dict[str, Any] | None:
    try:
        payload = uri[len("vmess://") :].split("#", 1)[0]
        data = json.loads(b64decode_text(payload))
        server = str(data.get("add") or "").strip()
        port = safe_int(data.get("port"))
        uuid = str(data.get("id") or "").strip()
        if not server or not port or not uuid:
            return None
        cipher = str(data.get("scy") or data.get("cipher") or "auto").lower()
        if cipher not in VMESS_CIPHERS:
            cipher = "auto"
        proxy: dict[str, Any] = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port,
            "uuid": uuid,
            "alterId": safe_int(data.get("aid"), 0),
            "cipher": cipher,
            "udp": True,
        }
        values: dict[str, list[str]] = defaultdict(list)
        fields = {
            "type": data.get("net") or data.get("network") or "tcp",
            "path": data.get("path") or "/",
            "host": data.get("host") or "",
            "servicename": data.get("path") or "",
            "security": data.get("tls") or data.get("security") or "",
            "sni": data.get("sni") or "",
            "alpn": data.get("alpn") or "",
            "fp": data.get("fp") or "",
            "insecure": data.get("insecure") or data.get("allowInsecure") or "",
            "pbk": data.get("pbk") or "",
            "sid": data.get("sid") or "",
            "ed": data.get("ed") or "",
        }
        for key, value in fields.items():
            if value not in (None, ""):
                values[key].append(str(value))
        if not apply_tls(proxy, values):
            return None
        if not apply_transport(proxy, values, protocol="vmess"):
            return None
        packet_encoding = str(data.get("packetEncoding") or "").strip()
        if packet_encoding:
            proxy["packet-encoding"] = packet_encoding
        return proxy
    except Exception:
        return None


def parse_trojan(uri: str, name: str) -> dict[str, Any] | None:
    try:
        parsed = urllib.parse.urlsplit(uri)
        server = parsed.hostname or ""
        port = parsed.port or 0
        password = urllib.parse.unquote(parsed.username or "")
        if not server or not port or not password:
            return None
        values = query_values(parsed.query)
        proxy: dict[str, Any] = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "udp": True,
        }
        if not apply_tls(proxy, values, implicit_tls=True, sni_key="sni"):
            return None
        if not apply_transport(proxy, values, protocol="trojan"):
            return None
        return proxy
    except Exception:
        return None


def parse_ss_plugin(raw: str) -> tuple[str, dict[str, Any]] | None:
    parts = [urllib.parse.unquote(item) for item in raw.split(";") if item]
    if not parts:
        return None
    plugin = parts[0].lower()
    options: dict[str, Any] = {}
    for item in parts[1:]:
        if "=" in item:
            key, value = item.split("=", 1)
            options[key] = value
        else:
            options[item] = True

    if plugin in {"obfs-local", "simple-obfs", "obfs"}:
        return "obfs", {
            key: value for key, value in options.items() if key in {"mode", "host"}
        }
    if plugin == "v2ray-plugin":
        mapped: dict[str, Any] = {}
        for key in ("mode", "host", "path", "mux"):
            if key in options:
                mapped[key] = options[key]
        if "tls" in options:
            mapped["tls"] = is_true(options["tls"])
        return "v2ray-plugin", mapped
    return None


def parse_ss(uri: str, name: str) -> dict[str, Any] | None:
    try:
        body = uri[len("ss://") :]
        main, _, fragment = body.partition("#")
        del fragment
        authority, separator, raw_query = main.partition("?")

        if "@" in authority:
            userinfo, host_port = authority.rsplit("@", 1)
            decoded_userinfo = urllib.parse.unquote(userinfo)
            if ":" not in decoded_userinfo:
                decoded_userinfo = b64decode_text(decoded_userinfo)
            method, password = decoded_userinfo.split(":", 1)
            server, port = split_host_port(host_port)
        else:
            decoded = b64decode_text(authority.rstrip("/"))
            userinfo, host_port = decoded.rsplit("@", 1)
            method, password = userinfo.split(":", 1)
            server, port = split_host_port(host_port)

        method = method.strip().lower()
        if method not in SS_CIPHERS or not password or not server or not port:
            return None
        proxy: dict[str, Any] = {
            "name": name,
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
            "udp": True,
        }
        values = query_values(raw_query)
        plugin_raw = qget(values, "plugin")
        if plugin_raw:
            parsed_plugin = parse_ss_plugin(plugin_raw)
            if not parsed_plugin:
                return None
            plugin, options = parsed_plugin
            proxy["plugin"] = plugin
            proxy["plugin-opts"] = options
        return proxy
    except Exception:
        return None


def parse_hysteria2(uri: str, name: str) -> dict[str, Any] | None:
    try:
        if uri.startswith("hy2://"):
            uri = "hysteria2://" + uri[len("hy2://") :]
        parsed = urllib.parse.urlsplit(uri)
        server = parsed.hostname or ""
        port = parsed.port or 0
        password = urllib.parse.unquote(parsed.username or "")
        values = query_values(parsed.query)
        password = password or qget(values, "auth", "password")
        if not server or not port or not password:
            return None
        proxy: dict[str, Any] = {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
        }
        sni = qget(values, "sni", "servername")
        if sni:
            proxy["sni"] = sni
        if is_true(qget(values, "insecure", "allowinsecure", "skip-cert-verify")):
            proxy["skip-cert-verify"] = True
        alpn = split_list(qget(values, "alpn"))
        if alpn:
            proxy["alpn"] = alpn
        obfs = qget(values, "obfs")
        obfs_password = qget(values, "obfs-password", "obfspassword")
        if obfs:
            if obfs != "salamander" or not obfs_password:
                return None
            proxy["obfs"] = obfs
            proxy["obfs-password"] = obfs_password
        ports = qget(values, "ports", "mport")
        if ports and re.fullmatch(r"[0-9,-]+", ports):
            proxy["ports"] = ports
        hop = qget(values, "hop-interval", "hopinterval")
        if hop:
            proxy["hop-interval"] = hop
        for source, target in (("up", "up"), ("down", "down")):
            value = qget(values, source)
            if value:
                proxy[target] = value
        return proxy
    except Exception:
        return None


def parse_proxy(uri: str, name: str) -> dict[str, Any] | None:
    uri = normalized_uri(uri)
    if uri.startswith("vless://"):
        return parse_vless(uri, name)
    if uri.startswith("vmess://"):
        return parse_vmess(uri, name)
    if uri.startswith("trojan://"):
        return parse_trojan(uri, name)
    if uri.startswith("ss://"):
        return parse_ss(uri, name)
    if uri.startswith(("hysteria2://", "hy2://")):
        return parse_hysteria2(uri, name)
    return None


def protocol(uri: str) -> str:
    return uri.split("://", 1)[0].lower()


def interleave_protocols(items: list[Candidate]) -> list[Candidate]:
    buckets: dict[str, deque[Candidate]] = defaultdict(deque)
    order: list[str] = []
    for item in items:
        if item.protocol not in buckets:
            order.append(item.protocol)
        buckets[item.protocol].append(item)

    result: list[Candidate] = []
    while True:
        added = False
        for proto in order:
            if buckets[proto]:
                result.append(buckets[proto].popleft())
                added = True
        if not added:
            return result


def load_candidates() -> tuple[dict[str, list[Candidate]], dict[str, dict[str, int]]]:
    entries = get_json(COUNTRY_API)
    country_files = sorted(
        (
            entry
            for entry in entries
            if entry.get("type") == "file"
            and str(entry.get("name", "")).lower().endswith(".txt")
            and entry.get("download_url")
        ),
        key=lambda entry: str(entry.get("name", "")).casefold(),
    )

    countries: dict[str, list[Candidate]] = {}
    metadata: dict[str, dict[str, int]] = {}
    serial = 0

    def download_country(entry: dict[str, Any]) -> str:
        return maybe_decode_subscription(http_get(str(entry["download_url"])))

    # Country files are independent; downloading them concurrently keeps the
    # hourly workflow comfortably below its timeout even when GitHub is slow.
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=DOWNLOAD_WORKERS
    ) as executor:
        downloaded = list(executor.map(download_country, country_files))

    for entry, text in zip(country_files, downloaded):
        country = Path(str(entry["name"])).stem.upper()
        raw_lines = [
            normalized_uri(line)
            for line in text.splitlines()
            if normalized_uri(line).startswith(SUPPORTED_PREFIXES)
        ]

        parsed_items: list[Candidate] = []
        seen_endpoints: set[str] = set()
        parse_rejected = 0
        duplicate_endpoints = 0

        for uri in raw_lines:
            serial += 1
            digest = hashlib.sha1(uri.encode("utf-8")).hexdigest()[:8]
            name = f"{country}-{serial:05d}-{digest}"
            proxy = parse_proxy(uri, name)
            if not proxy:
                parse_rejected += 1
                continue
            key = endpoint_key(str(proxy["server"]), int(proxy["port"]))
            if key in seen_endpoints:
                duplicate_endpoints += 1
                continue
            seen_endpoints.add(key)
            parsed_items.append(
                Candidate(
                    country=country,
                    uri=uri,
                    name=name,
                    protocol=protocol(uri),
                    endpoint=key,
                    proxy=proxy,
                )
            )

        ordered = interleave_protocols(parsed_items)
        eligible = ordered[:MAX_CANDIDATES_PER_COUNTRY]
        countries[country] = eligible
        metadata[country] = {
            "available": len(raw_lines),
            "parse_rejected": parse_rejected,
            "duplicate_endpoints": duplicate_endpoints,
            "eligible": len(eligible),
            "candidate_limit_skipped": max(0, len(ordered) - len(eligible)),
            "config_rejected": 0,
            "tested": 0,
            "working_found": 0,
            "selected": 0,
        }
        log(
            f"{country}: available={len(raw_lines)} eligible={len(eligible)} "
            f"parse_rejected={parse_rejected} duplicates={duplicate_endpoints}"
        )

    return countries, metadata


def make_config(candidates: list[Candidate], controller_port: int) -> dict[str, Any]:
    names = [item.name for item in candidates]
    return {
        "external-controller": f"127.0.0.1:{controller_port}",
        "secret": "",
        "log-level": "warning",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "proxies": [item.proxy for item in candidates],
        "proxy-groups": [
            {
                "name": "OPENRAY-CHECK",
                "type": "select",
                "proxies": names,
            }
        ],
        "rules": ["MATCH,OPENRAY-CHECK"],
    }


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def config_test(
    mihomo_bin: str,
    home: Path,
    candidates: list[Candidate],
    controller_port: int,
) -> tuple[bool, str]:
    test_path = home / "config-test.yaml"
    write_json(test_path, make_config(candidates, controller_port))
    result = subprocess.run(
        [mihomo_bin, "-t", "-d", str(home), "-f", str(test_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
        check=False,
    )
    return result.returncode == 0, result.stdout[-2000:]


def sanitize_config_candidates(
    mihomo_bin: str,
    home: Path,
    candidates: list[Candidate],
    controller_port: int,
) -> tuple[list[Candidate], set[str]]:
    """Drop only candidates that make Mihomo reject the whole config."""
    if not candidates:
        return [], set()
    valid, _ = config_test(mihomo_bin, home, candidates, controller_port)
    if valid:
        return candidates, set()

    rejected: set[str] = set()

    def split(items: list[Candidate]) -> list[Candidate]:
        ok, output = config_test(mihomo_bin, home, items, controller_port)
        if ok:
            return items
        if len(items) == 1:
            rejected.add(items[0].name)
            last_line = next(
                (line for line in reversed(output.splitlines()) if line.strip()),
                "invalid Mihomo config",
            )
            log(f"Config rejected {items[0].name}: {last_line[:240]}")
            return []
        middle = len(items) // 2
        return split(items[:middle]) + split(items[middle:])

    return split(candidates), rejected


def direct_preflight() -> None:
    for url in TEST_URLS:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "OpenRay-Balanced-Preflight/2.0"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            code = int(response.getcode())
        if code not in {200, 204}:
            raise RuntimeError(f"direct preflight failed for {url}: HTTP {code}")


def wait_for_controller(port: int, process: subprocess.Popen[Any]) -> None:
    url = f"http://127.0.0.1:{port}/version"
    deadline = time.time() + 20
    while time.time() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Mihomo exited with code {process.returncode}")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.getcode() == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError("Mihomo controller did not become ready")


def delay_check(port: int, name: str, test_url: str) -> int | None:
    encoded_name = urllib.parse.quote(name, safe="")
    params = urllib.parse.urlencode(
        {
            "url": test_url,
            "timeout": str(CHECK_TIMEOUT_MS),
            "expected": "200/204",
        }
    )
    url = f"http://127.0.0.1:{port}/proxies/{encoded_name}/delay?{params}"
    try:
        with urllib.request.urlopen(
            url, timeout=(CHECK_TIMEOUT_MS / 1000) + 5
        ) as response:
            payload = json.loads(response.read().decode("utf-8"))
        delay = payload.get("delay")
        return int(delay) if isinstance(delay, (int, float)) else None
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError):
        return None


def check_candidate(port: int, candidate: Candidate) -> tuple[bool, list[int]]:
    delays: list[int] = []
    for test_url in TEST_URLS:
        delay = delay_check(port, candidate.name, test_url)
        if delay is None:
            return False, delays
        delays.append(delay)
    return True, delays


def run_checks(
    port: int,
    countries: dict[str, list[Candidate]],
    metadata: dict[str, dict[str, int]],
) -> dict[str, list[Candidate]]:
    working: dict[str, list[Candidate]] = {country: [] for country in countries}
    offsets = {country: 0 for country in countries}
    round_number = 0

    while True:
        batch: list[Candidate] = []
        for country in sorted(countries):
            if len(working[country]) >= MAX_PER_COUNTRY:
                continue
            start = offsets[country]
            end = min(start + CHECK_BATCH_SIZE, len(countries[country]))
            if start < end:
                batch.extend(countries[country][start:end])
                offsets[country] = end

        if not batch:
            break

        round_number += 1
        log(f"Health-check round {round_number}: {len(batch)} candidates")
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=CHECK_WORKERS
        ) as executor:
            future_map = {
                executor.submit(check_candidate, port, item): item for item in batch
            }
            for future in concurrent.futures.as_completed(future_map):
                item = future_map[future]
                metadata[item.country]["tested"] += 1
                try:
                    passed, delays = future.result()
                except Exception:
                    passed, delays = False, []
                if passed:
                    working[item.country].append(item)
                    log(
                        f"PASS {item.country} {item.protocol} {item.endpoint} "
                        f"delays={delays}ms"
                    )

    for country in sorted(countries):
        metadata[country]["working_found"] = len(working[country])
        log(
            f"{country}: working={len(working[country])} "
            f"tested={metadata[country]['tested']}"
        )
    return working


def choose_diverse(items: list[Candidate], limit: int) -> list[Candidate]:
    selected: list[Candidate] = []
    used_protocols: set[str] = set()
    for item in items:
        if item.protocol not in used_protocols:
            selected.append(item)
            used_protocols.add(item.protocol)
            if len(selected) >= limit:
                return selected
    selected_names = {item.name for item in selected}
    for item in items:
        if item.name in selected_names:
            continue
        selected.append(item)
        if len(selected) >= limit:
            break
    return selected


def label_uri(uri: str, country: str) -> str:
    label = f"{country} | "
    try:
        if uri.startswith("vmess://"):
            payload = uri[len("vmess://") :].split("#", 1)[0]
            data = json.loads(b64decode_text(payload))
            old = str(data.get("ps", "")).strip()
            data["ps"] = label + old if old else country
            encoded = base64.b64encode(
                json.dumps(
                    data, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
            ).decode("ascii")
            return "vmess://" + encoded

        base, _, fragment = uri.partition("#")
        old = urllib.parse.unquote(fragment) if fragment else ""
        new = label + old if old else country
        return base + "#" + urllib.parse.quote(new, safe="| -_[]().")
    except Exception:
        return uri


def atomic_write(path: Path, content: str) -> None:
    path = path.resolve()
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_outputs(
    working: dict[str, list[Candidate]], metadata: dict[str, dict[str, int]]
) -> None:
    selected_by_country: dict[str, list[Candidate]] = {}

    for country in sorted(working):
        selected = choose_diverse(working[country], MAX_PER_COUNTRY)
        selected_by_country[country] = selected
        metadata[country]["selected"] = len(selected)

    nodes = [
        label_uri(item.uri, country)
        for country in sorted(selected_by_country)
        for item in selected_by_country[country]
    ]
    if len(nodes) < MIN_TOTAL_WORKING:
        raise RuntimeError(
            f"only {len(nodes)} nodes passed; refusing to replace the last subscription "
            f"(MIN_TOTAL_WORKING={MIN_TOTAL_WORKING})"
        )

    plain = "\n".join(nodes) + "\n"
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii") + "\n"

    failed = {
        country: f"0 working of {details['tested']} tested"
        for country, details in metadata.items()
        if details["selected"] == 0
    }
    per_country = {
        country: details["selected"] for country, details in sorted(metadata.items())
    }
    stats = {
        "countries": sum(1 for count in per_country.values() if count > 0),
        "countries_checked": len(per_country),
        "failed_countries": failed,
        "max_per_country": MAX_PER_COUNTRY,
        "per_country": per_country,
        "total_nodes": len(nodes),
    }
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checker": "Mihomo end-to-end HTTPS delay API",
        "test_urls": list(TEST_URLS),
        "check_timeout_ms": CHECK_TIMEOUT_MS,
        "max_per_country": MAX_PER_COUNTRY,
        "max_candidates_per_country": MAX_CANDIDATES_PER_COUNTRY,
        "total_tested": sum(item["tested"] for item in metadata.values()),
        "total_working_found": sum(
            item["working_found"] for item in metadata.values()
        ),
        "total_selected": len(nodes),
        "countries": dict(sorted(metadata.items())),
        "note": (
            "Checks run from GitHub Actions. A node can still be blocked by a "
            "specific mobile operator or fail after the workflow finishes."
        ),
    }

    atomic_write(Path("balanced.txt"), plain)
    atomic_write(Path("balanced_base64.txt"), encoded)
    atomic_write(
        Path("stats.json"),
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
    )
    atomic_write(
        Path("health_report.json"),
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
    )
    log(
        f"Done: {len(nodes)} working nodes across "
        f"{stats['countries']} countries"
    )


def terminate(process: subprocess.Popen[Any] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    if not TEST_URLS:
        raise RuntimeError("CHECK_URLS contains no URLs")
    mihomo_bin = os.environ.get("MIHOMO_BIN", "mihomo")
    resolved = shutil.which(mihomo_bin)
    if not resolved:
        raise RuntimeError(f"Mihomo binary not found: {mihomo_bin}")

    direct_preflight()
    countries, metadata = load_candidates()
    all_candidates = [item for values in countries.values() for item in values]
    if not all_candidates:
        raise RuntimeError("no supported candidates were parsed")

    work_dir = Path(tempfile.mkdtemp(prefix="openray-health-"))
    home = work_dir / "mihomo-home"
    home.mkdir(parents=True, exist_ok=True)
    controller_port = find_free_port()
    process: subprocess.Popen[Any] | None = None
    log_handle = None

    try:
        valid_candidates, rejected = sanitize_config_candidates(
            resolved, home, all_candidates, controller_port
        )
        if rejected:
            for country in countries:
                before = len(countries[country])
                countries[country] = [
                    item for item in countries[country] if item.name not in rejected
                ]
                metadata[country]["config_rejected"] = before - len(countries[country])
        if not valid_candidates:
            raise RuntimeError("Mihomo rejected every parsed candidate")

        final_config = work_dir / "healthcheck.yaml"
        write_json(final_config, make_config(valid_candidates, controller_port))
        log_path = work_dir / "mihomo.log"
        log_handle = log_path.open("w", encoding="utf-8")
        process = subprocess.Popen(
            [resolved, "-d", str(home), "-f", str(final_config)],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_controller(controller_port, process)
        working = run_checks(controller_port, countries, metadata)
        write_outputs(working, metadata)
    except Exception:
        if log_handle:
            log_handle.flush()
        log_path = work_dir / "mihomo.log"
        if log_path.exists():
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            if tail.strip():
                log("Mihomo log tail:\n" + tail)
        raise
    finally:
        terminate(process)
        if log_handle:
            log_handle.close()
        shutil.rmtree(work_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
