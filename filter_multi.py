#!/usr/bin/env python3
"""Build one small, country-balanced subscription from many public sources.

Country-sharded sources are preferred because their location is explicit.
Additional global subscriptions are accepted only when a country can be
derived from the node's flag, ISO code, or country name.  Everything is then
deduplicated and subjected to the same real end-to-end HTTPS checks.

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
import unicodedata
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

FASTNODES_API = (
    "https://api.github.com/repos/rtwo2/FastNodes/contents/"
    "sub/countries?ref=main"
)
SOLISPIRIT_API = (
    "https://api.github.com/repos/SoliSpirit/v2ray-configs/contents/"
    "Countries?ref=main"
)
TENIUM_API = (
    "https://api.github.com/repos/10ium/ScrapeAndCategorize/contents/"
    "output_configs?ref=main"
)

GLOBAL_SOURCES = (
    (
        "EbraSha",
        "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/"
        "refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    ),
    (
        "Epodonios",
        "https://raw.githubusercontent.com/Epodonios/v2ray-configs/"
        "main/All_Configs_Sub.txt",
    ),
    (
        "TGParse",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/"
        "main/splitted/mixed",
    ),
    (
        "Radikal",
        "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/"
        "main/verified/configs.txt",
    ),
    (
        "Mahdi",
        "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/"
        "master/sub/proxies.txt",
    ),
    (
        "Pawdroid",
        "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    ),
    (
        "BarryFar",
        "https://raw.githubusercontent.com/barry-far/V2ray-Config/"
        "main/All_Configs_Sub.txt",
    ),
    (
        "AbcConfigs",
        "https://raw.githubusercontent.com/FreeFolksOn/"
        "abc-configs-free-vpn-proxy-list/main/README.md",
    ),
)

SOURCE_ORDER = (
    "OpenRay",
    "Au1rxx",
    "igareck",
    "FastNodes",
    "SoliSpirit",
    "10ium",
    "EbraSha",
    "Epodonios",
    "TGParse",
    "Radikal",
    "Mahdi",
    "Pawdroid",
    "BarryFar",
    "AbcConfigs",
)
SOURCE_PER_COUNTRY_LIMIT = max(
    10, min(200, int(os.environ.get("SOURCE_PER_COUNTRY_LIMIT", "80")))
)
GLOBAL_SOURCE_LINE_LIMIT = max(
    1000, min(100000, int(os.environ.get("GLOBAL_SOURCE_LINE_LIMIT", "50000")))
)
DISCOVERY_WORKERS = max(
    1, min(32, int(os.environ.get("DISCOVERY_WORKERS", "16")))
)

ORIGINAL_HTTP_GET = core.http_get
ORIGINAL_GET_JSON = core.get_json
ORIGINAL_CHOOSE_DIVERSE = core.choose_diverse


ISO_CODES = set(
    """AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG
    BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK
    CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES
    ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT
    GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
    KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA
    MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA
    NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS
    PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO
    SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
    UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK""".split()
)


COUNTRY_FILENAME_CODES = {
    "albania": "AL",
    "argentina": "AR",
    "armenia": "AM",
    "australia": "AU",
    "austria": "AT",
    "azerbaijan": "AZ",
    "belarus": "BY",
    "belgium": "BE",
    "bosnia_and_herzegovina": "BA",
    "brazil": "BR",
    "bulgaria": "BG",
    "canada": "CA",
    "chile": "CL",
    "china": "CN",
    "colombia": "CO",
    "costa_rica": "CR",
    "croatia": "HR",
    "cyprus": "CY",
    "czechia": "CZ",
    "denmark": "DK",
    "estonia": "EE",
    "finland": "FI",
    "france": "FR",
    "germany": "DE",
    "greece": "GR",
    "hong_kong": "HK",
    "hungary": "HU",
    "iceland": "IS",
    "india": "IN",
    "indonesia": "ID",
    "iran": "IR",
    "iraq": "IQ",
    "ireland": "IE",
    "israel": "IL",
    "italy": "IT",
    "japan": "JP",
    "kazakhstan": "KZ",
    "latvia": "LV",
    "liechtenstein": "LI",
    "lithuania": "LT",
    "luxembourg": "LU",
    "malaysia": "MY",
    "maldives": "MV",
    "mauritius": "MU",
    "mexico": "MX",
    "moldova": "MD",
    "montenegro": "ME",
    "netherlands": "NL",
    "the_netherlands": "NL",
    "new_zealand": "NZ",
    "north_macedonia": "MK",
    "norway": "NO",
    "pakistan": "PK",
    "peru": "PE",
    "philippines": "PH",
    "poland": "PL",
    "portugal": "PT",
    "romania": "RO",
    "russia": "RU",
    "reunion": "RE",
    "samoa": "WS",
    "saudi_arabia": "SA",
    "serbia": "RS",
    "seychelles": "SC",
    "singapore": "SG",
    "slovakia": "SK",
    "slovenia": "SI",
    "south_africa": "ZA",
    "south_korea": "KR",
    "south_sudan": "SS",
    "spain": "ES",
    "sri_lanka": "LK",
    "sweden": "SE",
    "switzerland": "CH",
    "taiwan": "TW",
    "thailand": "TH",
    "tonga": "TO",
    "turkey": "TR",
    "turkiye": "TR",
    "uae": "AE",
    "united_arab_emirates": "AE",
    "uk": "GB",
    "united_kingdom": "GB",
    "usa": "US",
    "united_states": "US",
    "ukraine": "UA",
    "venezuela": "VE",
    "vietnam": "VN",
}


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


def normalized_country_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value)
    ascii_text = "".join(char for char in decomposed if not unicodedata.combining(char))
    return re.sub(r"[^a-z0-9]+", "_", ascii_text.casefold()).strip("_")


def country_from_filename(filename: str) -> str | None:
    stem = Path(filename).stem
    match = re.fullmatch(r"([A-Za-z]{2})(?:_part\d+)?", stem)
    if match:
        country = match.group(1).upper()
        return country if country in ISO_CODES else None
    return COUNTRY_FILENAME_CODES.get(normalized_country_text(stem))


def country_from_display_name(name: str) -> str | None:
    country = flag_to_country(name)
    if country in ISO_CODES:
        return country

    # Many collectors use labels such as "DE 1", "[US] node" or "FR | ...".
    for match in re.finditer(r"(?<![A-Za-z])([A-Z]{2})(?![A-Za-z])", name):
        country = match.group(1)
        if country in ISO_CODES:
            return country

    normalized = f"_{normalized_country_text(name)}_"
    for alias in sorted(COUNTRY_FILENAME_CODES, key=len, reverse=True):
        if f"_{alias}_" in normalized:
            return COUNTRY_FILENAME_CODES[alias]
    return None


def country_from_global_uri(uri: str) -> str | None:
    return country_from_display_name(display_name(uri))


def country_from_igareck(uri: str) -> str | None:
    return country_from_global_uri(uri)


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


def discover_fastnodes() -> list[tuple[str, str, str]]:
    tasks: list[tuple[str, str, str]] = []
    entries = get_json(FASTNODES_API)
    for entry in entries:
        name = str(entry.get("name", ""))
        # Use the first/base shard only.  Part files are enormous and the
        # checker already caps how many candidates each country needs.
        match = re.fullmatch(r"([A-Za-z]{2})\.txt", name)
        if entry.get("type") == "file" and match and entry.get("download_url"):
            country = match.group(1).upper()
            if country in ISO_CODES:
                tasks.append(("FastNodes", country, str(entry["download_url"])))
    return tasks


def discover_named_country_directory(
    source: str, api_url: str
) -> list[tuple[str, str, str]]:
    tasks: list[tuple[str, str, str]] = []
    entries = get_json(api_url)
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        name = str(entry.get("name", ""))
        if entry.get("type") != "file" or not entry.get("download_url"):
            continue
        country = country_from_filename(name)
        if not country or country == "XX":
            continue
        key = (country, str(entry["download_url"]))
        if key in seen:
            continue
        seen.add(key)
        tasks.append((source, country, str(entry["download_url"])))
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


def download_global_task(
    task: tuple[str, str]
) -> tuple[str, dict[str, list[str]], dict[str, int], str | None]:
    source, url = task
    try:
        lines = decoded_lines(ORIGINAL_HTTP_GET(url))
        buckets: dict[str, list[str]] = defaultdict(list)
        scanned = 0
        classified = 0
        for uri in lines[:GLOBAL_SOURCE_LINE_LIMIT]:
            scanned += 1
            country = country_from_global_uri(uri)
            if not country or country == "XX":
                continue
            classified += 1
            if len(buckets[country]) < SOURCE_PER_COUNTRY_LIMIT:
                buckets[country].append(uri)
        info = {
            "available": len(lines),
            "scanned": scanned,
            "classified": classified,
            "kept": sum(len(items) for items in buckets.values()),
        }
        return source, dict(buckets), info, None
    except Exception as exc:
        return source, {}, {}, f"{type(exc).__name__}: {exc}"


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

    discoverers = (
        ("OpenRay", discover_openray),
        ("Au1rxx", discover_au1rxx),
        ("FastNodes", discover_fastnodes),
        (
            "SoliSpirit",
            lambda: discover_named_country_directory("SoliSpirit", SOLISPIRIT_API),
        ),
        (
            "10ium",
            lambda: discover_named_country_directory("10ium", TENIUM_API),
        ),
    )
    for source, discover in discoverers:
        try:
            tasks.extend(discover())
        except Exception as exc:
            discovery_errors[source] = f"{type(exc).__name__}: {exc}"

    per_country_source: dict[str, dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    source_download_errors: dict[str, list[str]] = defaultdict(list)

    log(f"discovered {len(tasks)} explicit country shards from 5 repositories")
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=DISCOVERY_WORKERS
    ) as executor:
        results = list(executor.map(download_task, tasks))

    for source, country, lines, error in results:
        if error:
            source_download_errors[source].append(f"{country}: {error}")
            continue
        bucket = per_country_source[country][source]
        for uri in lines:
            if len(bucket) >= SOURCE_PER_COUNTRY_LIMIT:
                break
            bucket.append(tag_uri(uri, source))

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

    global_source_stats: dict[str, dict[str, int]] = {}
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(DISCOVERY_WORKERS, len(GLOBAL_SOURCES))
    ) as executor:
        global_results = list(executor.map(download_global_task, GLOBAL_SOURCES))

    for source, buckets, info, error in global_results:
        if error:
            source_download_errors[source].append(error)
            continue
        global_source_stats[source] = info
        for country, lines in buckets.items():
            bucket = per_country_source[country][source]
            for uri in lines:
                if len(bucket) >= SOURCE_PER_COUNTRY_LIMIT:
                    break
                bucket.append(tag_uri(uri, source))

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
        "global_source_line_limit": GLOBAL_SOURCE_LINE_LIMIT,
        "countries_discovered": len(virtual),
        "available_by_country_and_source": available,
        "global_source_stats": global_source_stats,
        "discovery_errors": discovery_errors,
        "download_errors": dict(source_download_errors),
    }
    log(
        f"virtual input: {len(virtual)} countries; "
        f"discovery_errors={len(discovery_errors)}"
    )
    return virtual, discovery


def choose_fastest_multi(
    items: list[core.Candidate], limit: int
) -> list[core.Candidate]:
    """Select the fastest working nodes across every downloaded source."""
    return sorted(
        items,
        key=lambda item: (
            item.latency_ms is None,
            item.latency_ms if item.latency_ms is not None else 10**9,
            source_of(item.uri),
            item.endpoint,
            item.name,
        ),
    )[:limit]


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
    core.choose_diverse = choose_fastest_multi

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
