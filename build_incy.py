#!/usr/bin/env python3
"""Build an INCY-only subscription with clean country names and AUTO nodes.

The input is the already health-checked ``balanced.txt`` produced by
``filter_multi.py``.  The output is a JSON array of full Xray configurations:

* one ``<flag> <Russian country name> AUTO`` config per country, using Xray's
  on-device ``leastPing`` balancer and Burst Observatory;
* one manual ``#1``, ``#2``, ... config for every selected physical node.

INCY imports every item in such an array as a separate server.  The first
proxy outbound tag becomes the name shown in the app.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
from collections import defaultdict
from pathlib import Path
from typing import Any

import filter_openray as core


INPUT_PATH = Path("balanced.txt")
OUTPUT_PATH = Path("balanced_incy.json")
STATS_PATH = Path("incy_stats.json")
COUNTRY_NAMES_PATH = Path(__file__).with_name("country_names_ru.json")

PROBE_URL = "https://cp.cloudflare.com/generate_204"
PROBE_INTERVAL = "30s"
PROBE_SAMPLING = 2
PROBE_TIMEOUT = "5s"

XRAY_SHADOWSOCKS_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
}


class UnsupportedNode(ValueError):
    """The share link works in Mihomo but cannot be represented safely here."""


def display_name(uri: str) -> str:
    try:
        if uri.startswith("vmess://"):
            payload = uri[len("vmess://") :].split("#", 1)[0]
            data = json.loads(core.b64decode_text(payload))
            return str(data.get("ps", "")).strip()
        _, _, fragment = uri.partition("#")
        return urllib.parse.unquote(fragment).strip() if fragment else ""
    except Exception:
        return ""


def country_from_uri(uri: str) -> str | None:
    match = re.match(r"^([A-Z]{2})\s*\|", display_name(uri))
    return match.group(1) if match else None


def country_flag(code: str) -> str:
    if not re.fullmatch(r"[A-Z]{2}", code):
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(char) - ord("A")) for char in code)


def header_value(headers: dict[str, Any], name: str) -> str:
    for key, value in headers.items():
        if str(key).casefold() == name.casefold():
            if isinstance(value, list):
                return str(value[0]) if value else ""
            return str(value)
    return ""


def boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "on"}


def tls_settings(proxy: dict[str, Any], *, implicit: bool = False) -> dict[str, Any]:
    reality = proxy.get("reality-opts")
    if isinstance(reality, dict):
        public_key = str(reality.get("public-key") or "").strip()
        if not public_key:
            raise UnsupportedNode("REALITY public key is missing")
        settings: dict[str, Any] = {
            "fingerprint": str(proxy.get("client-fingerprint") or "chrome"),
            "password": public_key,
            "shortId": str(reality.get("short-id") or ""),
        }
        server_name = str(proxy.get("servername") or proxy.get("sni") or "")
        if server_name:
            settings["serverName"] = server_name
        spider_x = str(reality.get("spider-x") or "")
        if spider_x:
            settings["spiderX"] = spider_x
        return {"security": "reality", "realitySettings": settings}

    if proxy.get("tls") or implicit:
        # Xray 26.3.27 removed ``allowInsecure`` completely.  Share links that
        # explicitly require certificate verification to be disabled cannot
        # be represented safely without a pinned certificate fingerprint, so
        # exclude them from the INCY output instead of creating a node that
        # passes JSON generation but fails at runtime.
        if boolish(proxy.get("skip-cert-verify", False)):
            raise UnsupportedNode(
                "TLS certificate verification is disabled in the source; "
                "current Xray requires a pinned certificate fingerprint"
            )
        settings: dict[str, Any] = {}
        server_name = str(proxy.get("servername") or proxy.get("sni") or "")
        if server_name:
            settings["serverName"] = server_name
        alpn = proxy.get("alpn")
        if isinstance(alpn, list) and alpn:
            settings["alpn"] = [str(item) for item in alpn]
        fingerprint = str(proxy.get("client-fingerprint") or "")
        if fingerprint:
            settings["fingerprint"] = fingerprint
        return {"security": "tls", "tlsSettings": settings}

    return {"security": "none"}


def append_early_data(path: str, amount: Any) -> str:
    try:
        value = int(amount)
    except (TypeError, ValueError):
        return path
    if value <= 0 or re.search(r"(?:^|[?&])ed=", path):
        return path
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}ed={value}"


def regular_stream_settings(proxy: dict[str, Any]) -> dict[str, Any]:
    network = str(proxy.get("network") or "tcp").casefold()
    stream: dict[str, Any]

    if network in {"", "tcp", "raw", "none"}:
        stream = {"method": "raw"}
    elif network == "ws":
        opts = proxy.get("ws-opts") or {}
        if not isinstance(opts, dict):
            opts = {}
        path = append_early_data(
            str(opts.get("path") or "/"), opts.get("max-early-data")
        )
        headers = opts.get("headers") if isinstance(opts.get("headers"), dict) else {}
        host = header_value(headers, "host")
        extra_headers = {
            str(key): str(value)
            for key, value in headers.items()
            if str(key).casefold() != "host"
        }
        if opts.get("v2ray-http-upgrade"):
            settings: dict[str, Any] = {"path": path}
            if host:
                settings["host"] = host
            if extra_headers:
                settings["headers"] = extra_headers
            stream = {"method": "httpupgrade", "httpupgradeSettings": settings}
        else:
            settings = {"path": path}
            if host:
                settings["host"] = host
            if extra_headers:
                settings["headers"] = extra_headers
            stream = {"method": "websocket", "wsSettings": settings}
    elif network == "grpc":
        opts = proxy.get("grpc-opts") or {}
        if not isinstance(opts, dict):
            opts = {}
        settings = {
            "serviceName": str(opts.get("grpc-service-name") or ""),
        }
        authority = str(opts.get("grpc-authority") or "")
        if authority:
            settings["authority"] = authority
        stream = {"method": "grpc", "grpcSettings": settings}
    elif network == "xhttp":
        opts = proxy.get("xhttp-opts") or {}
        if not isinstance(opts, dict):
            opts = {}
        settings = {"path": str(opts.get("path") or "/")}
        if opts.get("host"):
            settings["host"] = str(opts["host"])
        if opts.get("mode"):
            settings["mode"] = str(opts["mode"])
        inverse = {
            "no-grpc-header": "noGRPCHeader",
            "x-padding-bytes": "xPaddingBytes",
            "x-padding-obfs-mode": "xPaddingObfsMode",
            "x-padding-key": "xPaddingKey",
            "x-padding-header": "xPaddingHeader",
            "x-padding-placement": "xPaddingPlacement",
            "x-padding-method": "xPaddingMethod",
            "uplink-http-method": "uplinkHTTPMethod",
            "sc-max-each-post-bytes": "scMaxEachPostBytes",
            "sc-min-posts-interval-ms": "scMinPostsIntervalMs",
        }
        extra = {
            target: opts[source]
            for source, target in inverse.items()
            if source in opts
        }
        if extra:
            settings["extra"] = extra
        stream = {"method": "xhttp", "xhttpSettings": settings}
    else:
        raise UnsupportedNode(f"unsupported Xray transport: {network}")

    stream.update(tls_settings(proxy))
    return stream


def ss_plugin_stream(proxy: dict[str, Any]) -> dict[str, Any] | None:
    plugin = str(proxy.get("plugin") or "")
    if not plugin:
        return None
    opts = proxy.get("plugin-opts") or {}
    if not isinstance(opts, dict):
        opts = {}
    if plugin != "v2ray-plugin":
        raise UnsupportedNode(f"unsupported Shadowsocks plugin: {plugin}")
    mode = str(opts.get("mode") or "websocket").casefold()
    if mode not in {"websocket", "ws"}:
        raise UnsupportedNode(f"unsupported v2ray-plugin mode: {mode}")
    ws: dict[str, Any] = {"path": str(opts.get("path") or "/")}
    if opts.get("host"):
        ws["host"] = str(opts["host"])
    stream: dict[str, Any] = {"method": "websocket", "wsSettings": ws}
    if boolish(opts.get("tls")):
        tls: dict[str, Any] = {}
        if opts.get("host"):
            tls["serverName"] = str(opts["host"])
        stream.update({"security": "tls", "tlsSettings": tls})
    else:
        stream["security"] = "none"
    return stream


def parse_hop_interval(value: Any) -> int:
    match = re.search(r"\d+", str(value or ""))
    return max(5, int(match.group(0))) if match else 30


def hysteria_outbound(proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    if boolish(proxy.get("skip-cert-verify", False)):
        raise UnsupportedNode(
            "TLS certificate verification is disabled in the source; "
            "current Xray requires a pinned certificate fingerprint"
        )
    stream: dict[str, Any] = {
        "method": "hysteria",
        "security": "tls",
        "hysteriaSettings": {
            "version": 2,
            "auth": str(proxy["password"]),
        },
    }
    tls: dict[str, Any] = {}
    server_name = str(proxy.get("sni") or "")
    if server_name:
        tls["serverName"] = server_name
    alpn = proxy.get("alpn")
    if isinstance(alpn, list) and alpn:
        tls["alpn"] = [str(item) for item in alpn]
    stream["tlsSettings"] = tls

    finalmask: dict[str, Any] = {}
    obfs = str(proxy.get("obfs") or "")
    if obfs:
        password = str(proxy.get("obfs-password") or "")
        if obfs != "salamander" or not password:
            raise UnsupportedNode(f"unsupported Hysteria2 obfs: {obfs}")
        finalmask["udp"] = [
            {"type": "salamander", "settings": {"password": password}}
        ]

    quic: dict[str, Any] = {}
    if proxy.get("ports"):
        quic["udpHop"] = {
            "ports": str(proxy["ports"]),
            "interval": parse_hop_interval(proxy.get("hop-interval")),
        }
    if proxy.get("up"):
        quic["brutalUp"] = str(proxy["up"])
    if proxy.get("down"):
        quic["brutalDown"] = str(proxy["down"])
    if quic:
        finalmask["quicParams"] = quic
    if finalmask:
        stream["finalmask"] = finalmask

    return {
        "tag": tag,
        "protocol": "hysteria",
        "settings": {
            "version": 2,
            "address": str(proxy["server"]),
            "port": int(proxy["port"]),
        },
        "streamSettings": stream,
    }


def proxy_outbound(proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    protocol = str(proxy.get("type") or "")
    address = str(proxy.get("server") or "")
    port = int(proxy.get("port") or 0)
    if not address or not port:
        raise UnsupportedNode("server address or port is missing")

    if protocol == "hysteria2":
        return hysteria_outbound(proxy, tag)

    outbound: dict[str, Any] = {"tag": tag}
    if protocol == "vless":
        settings: dict[str, Any] = {
            "address": address,
            "port": port,
            "id": str(proxy["uuid"]),
            "encryption": str(proxy.get("encryption") or "none"),
            "level": 0,
        }
        if proxy.get("flow"):
            settings["flow"] = str(proxy["flow"])
        if proxy.get("packet-encoding"):
            settings["packetEncoding"] = str(proxy["packet-encoding"])
        outbound.update(
            {
                "protocol": "vless",
                "settings": settings,
                "streamSettings": regular_stream_settings(proxy),
            }
        )
    elif protocol == "vmess":
        if int(proxy.get("alterId") or 0) != 0:
            raise UnsupportedNode("legacy VMess alterId is not supported")
        cipher = str(proxy.get("cipher") or "auto")
        if cipher not in {"auto", "aes-128-gcm", "chacha20-poly1305"}:
            cipher = "auto"
        outbound.update(
            {
                "protocol": "vmess",
                "settings": {
                    "address": address,
                    "port": port,
                    "id": str(proxy["uuid"]),
                    "security": cipher,
                    "level": 0,
                },
                "streamSettings": regular_stream_settings(proxy),
            }
        )
    elif protocol == "trojan":
        outbound.update(
            {
                "protocol": "trojan",
                "settings": {
                    "address": address,
                    "port": port,
                    "password": str(proxy["password"]),
                    "level": 0,
                },
            }
        )
        stream = regular_stream_settings(proxy)
        stream.update(tls_settings(proxy, implicit=True))
        outbound["streamSettings"] = stream
    elif protocol == "ss":
        method = str(proxy.get("cipher") or "").strip().casefold()
        if method not in XRAY_SHADOWSOCKS_METHODS:
            raise UnsupportedNode(
                f"unsupported Xray Shadowsocks method: {method or 'missing'}"
            )
        outbound.update(
            {
                "protocol": "shadowsocks",
                "settings": {
                    "address": address,
                    "port": port,
                    "method": method,
                    "password": str(proxy["password"]),
                    "level": 0,
                },
            }
        )
        plugin_stream = ss_plugin_stream(proxy)
        if plugin_stream:
            outbound["streamSettings"] = plugin_stream
    else:
        raise UnsupportedNode(f"unsupported protocol: {protocol}")
    return outbound


def inbound() -> dict[str, Any]:
    return {
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "port": 10808,
        "protocol": "socks",
        "settings": {"udp": True},
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
        },
    }


def direct_and_block() -> list[dict[str, Any]]:
    return [
        {"tag": "direct", "protocol": "freedom"},
        {"tag": "block", "protocol": "blackhole"},
    ]


def manual_config(outbound: dict[str, Any], name: str, protocol: str) -> dict[str, Any]:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound()],
        "outbounds": [outbound, *direct_and_block()],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": name,
                }
            ],
        },
        "meta": {"serverDescription": f"Ручной сервер · {protocol.upper()}"},
    }


def auto_config(outbounds: list[dict[str, Any]], name: str, country: str) -> dict[str, Any]:
    tags = [str(item["tag"]) for item in outbounds]
    balancer_tag = f"incy-balancer-{country.lower()}"
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [inbound()],
        "outbounds": [*outbounds, *direct_and_block()],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": balancer_tag,
                }
            ],
            "balancers": [
                {
                    "tag": balancer_tag,
                    "selector": tags,
                    "fallbackTag": tags[0],
                    "strategy": {"type": "leastPing"},
                }
            ],
        },
        "burstObservatory": {
            "subjectSelector": tags,
            "pingConfig": {
                "destination": PROBE_URL,
                "connectivity": "",
                "interval": PROBE_INTERVAL,
                "sampling": PROBE_SAMPLING,
                "timeout": PROBE_TIMEOUT,
                "httpMethod": "HEAD",
            },
        },
        "stats": {},
        "meta": {
            "serverDescription": (
                f"Автовыбор самого быстрого из {len(outbounds)} рабочих серверов"
            )
        },
    }


def validate_config(config: dict[str, Any]) -> None:
    if not isinstance(config.get("inbounds"), list) or not isinstance(
        config.get("outbounds"), list
    ):
        raise ValueError("full Xray config must contain inbounds and outbounds")
    tags = [str(item.get("tag") or "") for item in config["outbounds"]]
    if len(tags) != len(set(tags)):
        raise ValueError("duplicate outbound tags")
    if not tags or not tags[0]:
        raise ValueError("first proxy outbound must have a display tag")


def xray_executable() -> str:
    requested = os.environ.get("XRAY_BIN", "").strip()
    if not requested:
        return ""
    executable = shutil.which(requested) or (
        requested if Path(requested).is_file() else ""
    )
    if not executable:
        raise RuntimeError(f"Xray binary not found: {requested}")
    return executable


def run_xray_test(
    executable: str, path: Path, config: dict[str, Any]
) -> subprocess.CompletedProcess[str]:
    path.write_text(
        json.dumps(config, ensure_ascii=False), encoding="utf-8"
    )
    return subprocess.run(
        [executable, "run", "-test", "-config", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )


def xray_error_summary(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in reversed(lines):
        if "Failed to start:" in line:
            return line.split("Failed to start:", 1)[1].strip()[-800:]
    return (lines[-1] if lines else "unknown Xray validation error")[-800:]


def filter_outbounds_with_xray(
    converted: list[tuple[dict[str, Any], str]],
    country: str,
    skipped: list[dict[str, str]],
) -> list[tuple[dict[str, Any], str]]:
    """Drop individual nodes rejected by the installed Xray version.

    Public sources regularly contain legacy or malformed share links.  A
    single incompatible node must not prevent every other country from being
    published, so validate each physical outbound before it reaches AUTO.
    """
    executable = xray_executable()
    if not executable:
        return converted

    accepted: list[tuple[dict[str, Any], str]] = []
    with tempfile.TemporaryDirectory(
        prefix=f"incy-xray-node-{country.lower()}-"
    ) as directory:
        path = Path(directory) / "config.json"
        for outbound, protocol in converted:
            copy = json.loads(json.dumps(outbound, ensure_ascii=False))
            tag = str(copy.get("tag") or "incy-node-test")
            probe = manual_config(copy, tag, protocol)
            validate_config(probe)
            result = run_xray_test(executable, path, probe)
            if result.returncode == 0:
                accepted.append((outbound, protocol))
                continue
            skipped.append(
                {
                    "country": country,
                    "protocol": protocol or "unknown",
                    "reason": f"Xray rejected node: {xray_error_summary(result.stdout)}",
                }
            )

    rejected = len(converted) - len(accepted)
    if rejected:
        print(
            f"Xray node precheck {country}: accepted={len(accepted)} "
            f"rejected={rejected}",
            flush=True,
        )
    return accepted


def validate_with_xray(configs: list[dict[str, Any]]) -> None:
    executable = xray_executable()
    if not executable:
        return

    with tempfile.TemporaryDirectory(prefix="incy-xray-test-") as directory:
        path = Path(directory) / "config.json"
        for index, config in enumerate(configs, 1):
            result = run_xray_test(executable, path, config)
            if result.returncode != 0:
                name = str(config["outbounds"][0].get("tag") or f"#{index}")
                tail = "\n".join(result.stdout.splitlines()[-12:])
                raise RuntimeError(f"Xray rejected {name}:\n{tail}")
    print(f"Xray validated all {len(configs)} INCY configs", flush=True)


def main() -> int:
    if not INPUT_PATH.exists():
        raise RuntimeError(f"missing input: {INPUT_PATH}")
    country_names = json.loads(COUNTRY_NAMES_PATH.read_text(encoding="utf-8"))

    grouped: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    input_nodes = 0
    parse_skipped: list[dict[str, str]] = []
    for line_number, raw_line in enumerate(
        INPUT_PATH.read_text(encoding="utf-8", errors="replace").splitlines(), 1
    ):
        uri = raw_line.strip()
        if not uri:
            continue
        input_nodes += 1
        country = country_from_uri(uri)
        if not country:
            parse_skipped.append(
                {"country": "??", "protocol": core.protocol(uri), "reason": "country label missing"}
            )
            continue
        proxy = core.parse_proxy(uri, f"incy-input-{line_number}")
        if not proxy:
            parse_skipped.append(
                {"country": country, "protocol": core.protocol(uri), "reason": "share link parse failed"}
            )
            continue
        grouped[country].append((uri, proxy))

    configs: list[dict[str, Any]] = []
    skipped = list(parse_skipped)
    per_country: dict[str, dict[str, Any]] = {}

    order = sorted(
        grouped,
        key=lambda code: (str(country_names.get(code, code)).casefold(), code),
    )
    for country in order:
        country_name = str(country_names.get(country) or country)
        prefix = f"{country_flag(country)} {country_name}"
        converted: list[tuple[dict[str, Any], str]] = []
        for index, (_, proxy) in enumerate(grouped[country], 1):
            internal_tag = f"incy-proxy-{country.lower()}-{index}"
            try:
                converted.append(
                    (proxy_outbound(proxy, internal_tag), str(proxy.get("type") or ""))
                )
            except (KeyError, TypeError, ValueError, UnsupportedNode) as exc:
                skipped.append(
                    {
                        "country": country,
                        "protocol": str(proxy.get("type") or "unknown"),
                        "reason": str(exc),
                    }
                )

        converted = filter_outbounds_with_xray(
            converted, country, skipped
        )

        if not converted:
            per_country[country] = {
                "name": country_name,
                "working_input": len(grouped[country]),
                "included": 0,
            }
            continue

        auto_name = f"{prefix} AUTO"
        auto_outbounds: list[dict[str, Any]] = []
        for index, (outbound, _) in enumerate(converted, 1):
            copy = json.loads(json.dumps(outbound, ensure_ascii=False))
            if index == 1:
                copy["tag"] = auto_name
            auto_outbounds.append(copy)
        auto = auto_config(auto_outbounds, auto_name, country)
        validate_config(auto)
        configs.append(auto)

        for index, (outbound, protocol) in enumerate(converted, 1):
            manual_name = f"{prefix} #{index}"
            copy = json.loads(json.dumps(outbound, ensure_ascii=False))
            copy["tag"] = manual_name
            manual = manual_config(copy, manual_name, protocol)
            validate_config(manual)
            configs.append(manual)

        per_country[country] = {
            "name": country_name,
            "working_input": len(grouped[country]),
            "included": len(converted),
            "configs": len(converted) + 1,
        }

    if not configs:
        raise RuntimeError("no INCY-compatible nodes were produced")

    validate_with_xray(configs)

    stats = {
        "format": "INCY full Xray config array",
        "input_nodes": input_nodes,
        "physical_nodes": sum(item["included"] for item in per_country.values()),
        "countries": sum(1 for item in per_country.values() if item["included"] > 0),
        "total_configs": len(configs),
        "auto_configs": sum(1 for item in per_country.values() if item["included"] > 0),
        "manual_configs": sum(item["included"] for item in per_country.values()),
        "per_country": dict(sorted(per_country.items())),
        "skipped": skipped,
    }

    core.atomic_write(
        OUTPUT_PATH,
        json.dumps(configs, ensure_ascii=False, separators=(",", ":")) + "\n",
    )
    core.atomic_write(
        STATS_PATH,
        json.dumps(stats, ensure_ascii=False, indent=2) + "\n",
    )
    print(
        f"INCY: {stats['physical_nodes']} physical nodes, "
        f"{stats['countries']} countries, {stats['total_configs']} configs, "
        f"{len(skipped)} skipped",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
