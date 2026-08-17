#!/usr/bin/env python3
import base64
import json
import os
import re
import urllib.request
import urllib.parse

OWNER = "sakha1370"
REPO = "OpenRay"
BRANCH = "main"
COUNTRY_API = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/output/country?ref={BRANCH}"
MAX_PER_COUNTRY = int(os.environ.get("MAX_PER_COUNTRY", "5"))

# Protocols that are the safest fit for INCY/Xray-style imports.
SUPPORTED = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://")


def http_get(url: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "OpenRay-Balanced-Subscription/1.0",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read()


def maybe_decode_subscription(raw: bytes) -> str:
    """Return plain URI-per-line subscription text from raw or base64 input."""
    text = raw.decode("utf-8", errors="replace").strip()
    if any(s in text for s in SUPPORTED):
        return text

    compact = re.sub(r"\s+", "", text)
    if not compact:
        return ""

    # Try standard/url-safe base64; subscriptions often omit padding.
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    for altchars in (None, b"-_"):
        try:
            decoded = base64.b64decode(padded, altchars=altchars, validate=False)
            out = decoded.decode("utf-8", errors="replace").strip()
            if any(s in out for s in SUPPORTED):
                return out
        except Exception:
            pass
    return text


def endpoint_key(uri: str) -> str:
    """Best-effort key to avoid duplicates of the same server."""
    try:
        if uri.startswith("vmess://"):
            payload = uri[len("vmess://"):].split("#", 1)[0]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            obj = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
            return f"vmess|{obj.get('add','')}|{obj.get('port','')}|{obj.get('id','')}"
        p = urllib.parse.urlsplit(uri)
        return f"{p.scheme}|{p.hostname or ''}|{p.port or ''}|{p.username or ''}"
    except Exception:
        return uri.split("#", 1)[0]


def protocol(uri: str) -> str:
    return uri.split("://", 1)[0].lower()


def label_uri(uri: str, cc: str) -> str:
    """Prefix display name with country code while keeping config semantics."""
    label = f"{cc} | "
    try:
        if uri.startswith("vmess://"):
            payload = uri[len("vmess://"):].split("#", 1)[0]
            payload += "=" * ((4 - len(payload) % 4) % 4)
            obj = json.loads(base64.b64decode(payload).decode("utf-8", errors="ignore"))
            old = str(obj.get("ps", "")).strip()
            obj["ps"] = label + old if old else cc
            enc = base64.b64encode(
                json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
            ).decode()
            return "vmess://" + enc

        # For URI-style protocols the fragment is the display name.
        base, _, frag = uri.partition("#")
        old = urllib.parse.unquote(frag) if frag else ""
        new = label + old if old else cc
        return base + "#" + urllib.parse.quote(new, safe="| -_[]().")
    except Exception:
        return uri


def select_balanced(lines, limit):
    """Prefer protocol diversity first, then fill remaining slots."""
    valid = []
    seen = set()
    for line in lines:
        u = line.strip()
        if not u.startswith(SUPPORTED):
            continue
        key = endpoint_key(u)
        if key in seen:
            continue
        seen.add(key)
        valid.append(u)

    # First pass: one node per protocol.
    selected = []
    used_proto = set()
    for u in valid:
        pr = protocol(u)
        if pr not in used_proto:
            selected.append(u)
            used_proto.add(pr)
            if len(selected) >= limit:
                return selected

    # Second pass: fill to the requested limit.
    selected_keys = {endpoint_key(u) for u in selected}
    for u in valid:
        if endpoint_key(u) in selected_keys:
            continue
        selected.append(u)
        selected_keys.add(endpoint_key(u))
        if len(selected) >= limit:
            break
    return selected


def main():
    entries = json.loads(http_get(COUNTRY_API).decode("utf-8"))
    country_files = sorted(
        (
            e for e in entries
            if e.get("type") == "file"
            and e.get("name", "").lower().endswith(".txt")
            and e.get("download_url")
        ),
        key=lambda e: e.get("name", "").casefold(),
    )

    merged = []
    stats = {}
    failed = {}

    for entry in country_files:
        cc = entry["name"].rsplit(".", 1)[0].upper()
        # Skip unknown/geolocation-failed bucket.
        if cc == "XX":
            continue
        try:
            text = maybe_decode_subscription(http_get(entry["download_url"]))
            lines = text.splitlines()
            picked = select_balanced(lines, MAX_PER_COUNTRY)
            if not picked:
                continue
            labeled = [label_uri(u, cc) for u in picked]
            merged.extend(labeled)
            stats[cc] = len(labeled)
        except Exception as exc:
            failed[cc] = str(exc)

    # Global de-duplication, preserving country order.
    out = []
    seen = set()
    for u in merged:
        key = endpoint_key(u)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)

    plain = "\n".join(out) + ("\n" if out else "")
    b64 = base64.b64encode(plain.encode("utf-8")).decode("ascii") + "\n"

    with open("balanced.txt", "w", encoding="utf-8", newline="\n") as f:
        f.write(plain)
    with open("balanced_base64.txt", "w", encoding="ascii", newline="\n") as f:
        f.write(b64)
    with open("stats.json", "w", encoding="utf-8") as f:
        json.dump(
            {
                "max_per_country": MAX_PER_COUNTRY,
                "countries": len(stats),
                "total_nodes": len(out),
                "per_country": stats,
                "failed_countries": failed,
            },
            f,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )

    print(f"Countries: {len(stats)}")
    print(f"Nodes: {len(out)}")
    if failed:
        print("Failed:", failed)


if __name__ == "__main__":
    main()
