"""Known-bad JA3 blocklist: embedded seed + optional refreshable feed.

Design honesty: ARGUS does not ship fabricated "JA3 → named malware" attributions.
The embedded seed (``data/ja3_blocklist.json``) contains only entries whose
provenance is stated (e.g. the test fixture). Real threat intel is layered on via
``update_from_feed()`` (default: abuse.ch SSLBL JA3 feed), cached locally so the
detection still works offline afterwards.
"""

from __future__ import annotations

import json
import os
import urllib.request

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
_EMBEDDED = os.path.join(_DATA_DIR, "ja3_blocklist.json")
_CACHE = os.path.expanduser("~/.argus/ja3_feed.json")

# abuse.ch SSLBL JA3 fingerprint blacklist (CSV). May change/deprecate over time;
# override with --ja3-feed-url. Updating is opt-in and the only network operation.
DEFAULT_FEED_URL = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv"


def _read_json(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    # drop documentation keys like "_meta"
    return {k: v for k, v in data.items() if not k.startswith("_")}


def load_blocklist() -> dict[str, dict]:
    """Embedded seed merged with any locally-cached feed (cache wins)."""
    blocklist = _read_json(_EMBEDDED)
    blocklist.update(_read_json(_CACHE))
    return blocklist


def _parse_feed_csv(text: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        md5 = parts[0].lower()
        if len(md5) != 32:
            continue  # header or malformed row
        label = parts[-1] if len(parts) > 1 else "abuse.ch SSLBL"
        out[md5] = {"label": label, "source": "abuse.ch SSLBL"}
    return out


def update_from_feed(url: str = DEFAULT_FEED_URL, timeout: int = 20) -> int:
    """Fetch the feed and cache it locally. Returns the number of entries.

    Raises on network/parse failure so the CLI can report it clearly.
    """
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310
        text = resp.read().decode("utf-8", errors="replace")
    entries = _parse_feed_csv(text)
    if not entries:
        raise ValueError("feed returned no usable JA3 entries")
    os.makedirs(os.path.dirname(_CACHE), exist_ok=True)
    with open(_CACHE, "w", encoding="utf-8") as fh:
        json.dump(entries, fh, indent=2)
    return len(entries)
