#!/usr/bin/env python3
"""Build one small, country-balanced subscription from several public sources.

Sources:
- OpenRay country shards
- Au1rxx/free-vpn-subscriptions country V2Ray shards
- igareck/vpn-configs-for-russia Mobile-150

The heavy lifting (URI parsing + real end-to-end Mihomo HTTPS checks) stays in
filter_openray.py. This wrapper only discovers/merges sources and feeds them to
that checker as one virtual country directory.
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import re
import urllib.parse
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import filter_openray as core


OPENRAY_API = (
    "https://api.github.com/repos/sakha1370/OpenRay/contents/output/country?ref=main"
)
AU1RXX_API = (
    "https://api.github.com/repos/Au1rxx/free-vpn-subscriptions/contents/"
    "output/by-country?ref=main"
)
IGARECK_URL = (
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/"
    "main/BLACK_VLESS_RUS_mobile.txt"
)

SOURCE_ORDER = ("OpenRay", "Au1rxx", "igareck")
SOURCE_PER_COUNTRY_LIMIT = max(
    10, min(200, int(os.environ.get("SOURCE_PER_COUNTRY_LIMIT", "80")))
)
DISCOVERY_WORKERS = max(
    1, min(32, int(os.environ.get("DISCOVERY_WORKERS", "16")))
)

ORIGINAL_HTTP_GET = core.http_get
ORIGINAL_GET_JSON = core.get_json
ORIGINAL_CHOOSE_DIVERSE = core.choose_diverse


def log(message: str) -> None:
    print(f"[multi] {message}", flush=True)


def get_json(url: str) -> Any:
    return json.loads(ORIGINAL_HTTP_GET(url).decode("utf-8"))


def decoded_lines(raw: bytes) -> list[str]:
    text = core.maybe_decode_subscription(raw)
    result: list[str] = []
    for raw_line in text.splitlines():
        line = core.normalized_uri(raw_line)
        if line.startswith(core.SUPPORTED_PREFIXES):
            result.append(line)
    return result


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


def tag_uri(uri: str, source: str) -> str:
    """Put the source in the visible node name without changing the endpoint."""
    prefix = f"{source} | "
    try:
        if uri.startswith("vmess://"):
            payload = uri[len("vmess://") :].split("#", 1)[0]
            data = json.loads(core.b64decode_text(payload))
            old = str(data.get("ps", "")).strip()
            if not old.startswith(prefix):
                data["ps"] = prefix + old if old else source
            encoded = base64.b64encode(
                json.dumps(
                    data, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
            ).decode("ascii")
            return "vmess://" + encoded

        base, _, fragment = uri.partition("#")
        old = urllib.parse.unquote(fragment).strip() if fragment else ""
        new = old if old.startswith(prefix) else (prefix + old if old else source)
        return base + "#" + urllib.parse.quote(new, safe="| -_[]().,")
    except Exception:
        return uri


def source_of(uri: str) -> str:
    name = display_name(uri)
    for source in SOURCE_ORDER:
        if name.startswith(source + " |") or name == source:
            return source
    return "unknown"


def flag_to_country(text: str) -> str | None:
    """Extract an ISO alpha-2 code from a flag emoji in a display name."""
    for index in range(len(text) - 1):
        first = ord(text[index])
        second = ord(text[index + 1])
        if 0x1F1E6 <= first <= 0x1F1FF and 0x1F1E6 <= second <= 0x1F1FF:
            return (
                chr(ord("A") + first - 0x1F1E6)
                + chr(ord("A") + second - 0x1F1E6)
            )
    return None


def country_from_igareck(uri: str) -> str | None:
    country = flag_to_country(display_name(uri))
    if country and re.fullmatch(r"[A-Z]{2}", country):
        return country
    return None


def discover_openray() -> list[tuple[str, str, str]]:
    tasks: list[tuple[str, str, str]] = []
    entries = get_json(OPENRAY_API)
    for entry in entries:
        name = str(entry.get("name", ""))
        match = re.fullmatch(r"([A-Za-z]{2})\.txt", name)
        if entry.get("type") == "file" and match and entry.get("download_url"):
            country = match.group(1).upper()
            if country != "XX":
                tasks.append(("OpenRay", country, str(entry["download_url"])))
    return tasks


def discover_au1rxx() -> list[tuple[str, str, str]]:
    tasks: list[tuple[str, str, str]] = []
    entries = get_json(AU1RXX_API)
    for entry in entries:
        name = str(entry.get("name", ""))
        match = re.fullmatch(r"v2ray-base64-([A-Za-z]{2})\.txt", name)
        if entry.get("type") == "file" and match and entry.get("download_url"):
            tasks.append(
                ("Au1rxx", match.group(1).upper(), str(entry["download_url"]))
            )
    return tasks


def download_task(
    task: tuple[str, str, str]
) -> tuple[str, str, list[str], str | None]:
    source, country, url = task
    try:
        lines = decoded_lines(ORIGINAL_HTTP_GET(url))
        return source, country, lines[:SOURCE_PER_COUNTRY_LIMIT], None
    except Exception as exc:
        return source, country, [], f"{type(exc).__name__}: {exc}"


def round_robin_sources(
    by_source: dict[str, list[str]], *, limit_per_source: int
) -> list[str]:
    queues = {
        source: deque(lines[:limit_per_source])
        for source, lines in by_source.items()
        if lines
    }
    result: list[str] = []
    while queues:
        progressed = False
        for source in SOURCE_ORDER:
            queue = queues.get(source)
            if not queue:
                continue
            result.append(queue.popleft())
            progressed = True
            if not queue:
                queues.pop(source, None)
        if not progressed:
            break
    return result


def build_virtual_countries() -> tuple[dict[str, bytes], dict[str, Any]]:
    tasks: list[tuple[str, str, str]] = []
    discovery_errors: dict[str, str] = {}

    try:
        tasks.extend(discover_openray())
    except Exception as exc:
        discovery_errors["OpenRay"] = f"{type(exc).__name__}: {exc}"
    try:
        tasks.extend(discover_au1rxx())
    except Exception as exc:
        discovery_errors["Au1rxx"] = f"{type(exc).__name__}: {exc}"

    per_country_source: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    source_download_errors: dict[str, list[str]] = defaultdict(list)

    log(f"discovered {len(tasks)} country shards from OpenRay + Au1rxx")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=DISCOVERY_WORKERS
    ) as executor:
        results = list(executor.map(download_task, tasks))

    for source, country, lines, error in results:
        if error:
            source_download_errors[source].append(f"{country}: {error}")
            continue
        for uri in lines:
            per_country_source[country][source].append(tag_uri(uri, source))

    # igareck is a compact mobile list whose names already contain country flags.
    try:
        igareck_lines = decoded_lines(ORIGINAL_HTTP_GET(IGARECK_URL))
        for uri in igareck_lines:
            country = country_from_igareck(uri)
            if not country or country == "XX":
                continue
            bucket = per_country_source[country]["igareck"]
            if len(bucket) < SOURCE_PER_COUNTRY_LIMIT:
                bucket.append(tag_uri(uri, "igareck"))
    except Exception as exc:
        discovery_errors["igareck"] = f"{type(exc).__name__}: {exc}"

    virtual: dict[str, bytes] = {}
    available: dict[str, dict[str, int]] = {}
    for country in sorted(per_country_source):
        source_map = per_country_source[country]
        available[country] = {
            source: len(source_map.get(source, [])) for source in SOURCE_ORDER
        }
        merged = round_robin_sources(
            source_map, limit_per_source=SOURCE_PER_COUNTRY_LIMIT
        )
        if merged:
            virtual[country] = ("\n".join(merged) + "\n").encode("utf-8")

    discovery = {
        "sources": list(SOURCE_ORDER),
        "source_per_country_limit": SOURCE_PER_COUNTRY_LIMIT,
        "countries_discovered": len(virtual),
        "available_by_country_and_source": available,
        "discovery_errors": discovery_errors,
        "download_errors": dict(source_download_errors),
    }
    log(
        f"virtual input: {len(virtual)} countries; "
        f"discovery_errors={len(discovery_errors)}"
    )
    return virtual, discovery


def choose_diverse_multi(
    items: list[core.Candidate], limit: int
) -> list[core.Candidate]:
    """Prefer source diversity first, then protocol diversity, then fill."""
    selected: list[core.Candidate] = []
    selected_names: set[str] = set()
    used_sources: set[str] = set()
    used_protocols: set[str] = set()

    # First: one working node from each source when possible.
    for item in items:
        source = source_of(item.uri)
        if source in used_sources:
            continue
        selected.append(item)
        selected_names.add(item.name)
        used_sources.add(source)
        used_protocols.add(item.protocol)
        if len(selected) >= limit:
            return selected

    # Second: protocols not represented yet.
    for item in items:
        if item.name in selected_names or item.protocol in used_protocols:
            continue
        selected.append(item)
        selected_names.add(item.name)
        used_protocols.add(item.protocol)
        if len(selected) >= limit:
            return selected

    # Third: fill remaining slots round-robin across sources.
    buckets: dict[str, deque[core.Candidate]] = defaultdict(deque)
    for item in items:
        if item.name not in selected_names:
            buckets[source_of(item.uri)].append(item)

    source_order = list(SOURCE_ORDER) + [
        source for source in sorted(buckets) if source not in SOURCE_ORDER
    ]
    while len(selected) < limit:
        progressed = False
        for source in source_order:
            if not buckets[source]:
                continue
            item = buckets[source].popleft()
            selected.append(item)
            selected_names.add(item.name)
            progressed = True
            if len(selected) >= limit:
                break
        if not progressed:
            break
    return selected


def selected_source_counts(path: Path) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    if not path.exists():
        return {}
    for raw_line in path.read_text(
        encoding="utf-8", errors="replace"
    ).splitlines():
        uri = raw_line.strip()
        if not uri.startswith(core.SUPPORTED_PREFIXES):
            continue
        name = display_name(uri)
        found = "unknown"
        for source in SOURCE_ORDER:
            if (
                f"| {source} |" in name
                or name.startswith(source + " |")
                or name.endswith("| " + source)
                or name == source
            ):
                found = source
                break
        counts[found] += 1
    return dict(sorted(counts.items()))


def main() -> int:
    virtual, discovery = build_virtual_countries()
    if not virtual:
        raise RuntimeError("no country data could be built from any source")

    original_http_get = core.http_get
    original_get_json = core.get_json
    original_choose = core.choose_diverse

    def virtual_get_json(url: str) -> Any:
        if url == core.COUNTRY_API:
            return [
                {
                    "type": "file",
                    "name": f"{country}.txt",
                    "download_url": f"multi://{country}",
                }
                for country in sorted(virtual)
            ]
        return original_get_json(url)

    def virtual_http_get(url: str, timeout: float = 45) -> bytes:
        if url.startswith("multi://"):
            country = url[len("multi://") :].upper()
            if country not in virtual:
                raise RuntimeError(f"unknown virtual country: {country}")
            return virtual[country]
        return original_http_get(url, timeout)

    core.get_json = virtual_get_json
    core.http_get = virtual_http_get
    core.choose_diverse = choose_diverse_multi

    try:
        result = core.main()
    finally:
        core.get_json = original_get_json
        core.http_get = original_http_get
        core.choose_diverse = original_choose

    discovery["selected_by_source"] = selected_source_counts(
        Path("balanced.txt")
    )
    core.atomic_write(
        Path("sources.json"),
        json.dumps(discovery, ensure_ascii=False, indent=2) + "\n",
    )
    log(f"selected by source: {discovery['selected_by_source']}")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
