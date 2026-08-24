#!/usr/bin/env python3
"""
SPECTRA watch — watchlists, tracker fingerprinting, and the finder/sweep logic.

This is what turns the surface console into a purpose tool for two opposite jobs:

  FINDER  — locate YOUR OWN devices in a crowd (asset recovery). Load an
            allowlist of your tracker MACs; everything else is muted; your
            devices rank by signal so you can walk one down.

  SWEEP   — find devices that shouldn't be there (TSCM). Load a blocklist, and
            anything on it — or any unlisted device that fingerprints as a
            tracker — flags loud.

Both share one honest reality carried from the rest of SPECTRA:
  * Many modern trackers (AirTag / Find My, some SmartTags) ROTATE their MAC.
    A static MAC list will not hold them. So matching is two-layered: exact MAC
    for fixed-address devices, plus advertisement fingerprint (Find My / Tile /
    SmartTag) that survives rotation.
  * Signal gets you 'warmer / colder' as you move. Bearing is not measured —
    a single antenna can't. Real direction needs a directional antenna you aim.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

WATCH_PATH = Path.home() / ".spectra" / "watchlist.json"

_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}|\b[0-9A-Fa-f]{12}\b")


def norm_mac(raw: str) -> str:
    hexs = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
    if len(hexs) != 12:
        return (raw or "").upper()
    return ":".join(hexs[i : i + 2] for i in range(0, 12, 2)).upper()


def parse_macs(text: str) -> list[tuple[str, str]]:
    """Extract (mac, label) pairs from freeform text or CSV.

    Accepts one-per-line MACs (colon, dash, or bare 12-hex), optionally followed
    by a comma/semicolon/tab and a label. Blank lines and #comments are skipped.
    Junk lines without a MAC are ignored rather than erroring.
    """
    out: list[tuple[str, str]] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _MAC_RE.search(line)
        if not m:
            continue
        mac = norm_mac(m.group(0))
        # label = whatever follows the first delimiter after the MAC, if any
        rest = line[m.end():].lstrip(" ,;\t")
        label = rest.split(",")[0].strip() if rest else ""
        # or a CSV where MAC is second column and label first — handle simply:
        if not label:
            pre = line[: m.start()].strip().rstrip(",;\t")
            if pre and "," in line:
                label = pre
        out.append((mac, label))
    return out


# ---------------------------------------------------------------------------
# tracker fingerprints — survive MAC rotation
# ---------------------------------------------------------------------------

# Two categories, and the distinction matters more than it looks.
#
#   locator   — a device whose PURPOSE is to be findable: AirTag, Tile, SmartTag,
#               Chipolo. An unlisted one in your space is worth investigating.
#   accessory — a device that merely uses the same pairing machinery: Fast Pair
#               earbuds, speakers, a phone. Flagging these as trackers is what
#               makes a TSCM sweep in a coffee shop useless, because every pair
#               of headphones in the room lights up.
#
# Needles are matched on WORD BOUNDARIES, so "Tile" no longer matches "Reptile"
# or "Tilebridge". Vendor names alone are never enough: "samsung" used to be a
# SmartTag needle, which meant every Samsung phone, TV and pair of earbuds
# fingerprinted as a tracking tag.
TRACKER_SIGNATURES: dict[str, dict[str, Any]] = {
    "airtag": {
        "name": "Apple AirTag / Find My",
        "category": "locator",
        "needles": [r"air\s?tag", r"find\s?my"],
    },
    "tile": {
        "name": "Tile tracker",
        "category": "locator",
        "needles": [r"tile"],
        # Tile's own advertisement carries the company UUID; the bare word
        # appears in plenty of unrelated product names.
        "exclude": [r"reptile", r"tilebridge", r"textile"],
    },
    "smarttag": {
        "name": "Samsung SmartTag",
        "category": "locator",
        "needles": [r"smart\s?tag\d*", r"galaxy\s?smarttag\d*"],
    },
    "chipolo": {
        "name": "Chipolo",
        "category": "locator",
        "needles": [r"chipolo"],
    },
    "fastpair": {
        "name": "Google Fast Pair accessory",
        "category": "accessory",
        "needles": [r"fast\s?pair"],
    },
}


def match_tracker(ble_hint: str | None) -> dict[str, str] | None:
    """Does this BLE advertisement fingerprint as a known tracker family?

    Returns kind, name and category. Category is what callers should branch on:
    a "locator" is a tracking tag, an "accessory" is a headset or speaker that
    happens to share a pairing protocol.
    """
    if not ble_hint:
        return None
    h = ble_hint.lower()
    for key, sig in TRACKER_SIGNATURES.items():
        if any(re.search(rf"\b{n}\b", h) for n in sig.get("exclude", [])):
            continue
        if any(re.search(rf"\b{n}\b", h) for n in sig["needles"]):
            return {
                "kind": key,
                "name": sig["name"],
                "category": sig.get("category", "locator"),
            }
    return None


# ---------------------------------------------------------------------------
# watchlist store
# ---------------------------------------------------------------------------


class Watchlist:
    def __init__(self):
        self.allow: dict[str, dict] = {}
        self.block: dict[str, dict] = {}
        self._load()

    def _load(self):
        if WATCH_PATH.exists():
            try:
                data = json.loads(WATCH_PATH.read_text())
                self.allow = data.get("allow", {})
                self.block = data.get("block", {})
            except Exception:
                pass

    def _save(self):
        WATCH_PATH.parent.mkdir(parents=True, exist_ok=True)
        WATCH_PATH.write_text(json.dumps({"allow": self.allow, "block": self.block}))
        try:
            WATCH_PATH.chmod(0o600)
        except OSError:
            pass

    def _bucket(self, which: str) -> dict:
        return self.allow if which == "allow" else self.block

    def add(self, mac: str, which: str = "allow", label: str = "") -> bool:
        mac = norm_mac(mac)
        if not mac or len(mac) != 17:
            return False
        self._bucket(which)[mac] = {"label": label or "", "added": int(time.time())}
        self._save()
        return True

    def add_many(self, pairs: list[tuple[str, str]], which: str = "allow") -> int:
        n = 0
        for mac, label in pairs:
            mac = norm_mac(mac)
            if len(mac) == 17:
                self._bucket(which)[mac] = {"label": label or "", "added": int(time.time())}
                n += 1
        if n:
            self._save()
        return n

    def import_text(self, text: str, which: str = "allow") -> int:
        return self.add_many(parse_macs(text), which)

    def remove(self, mac: str, which: str = "allow") -> None:
        self._bucket(which).pop(norm_mac(mac), None)
        self._save()

    def clear(self, which: str) -> None:
        self._bucket(which).clear()
        self._save()

    def status(self, mac: str) -> str:
        mac = norm_mac(mac)
        if mac in self.allow:
            return "allow"
        if mac in self.block:
            return "block"
        return "unknown"

    def label(self, mac: str) -> str:
        mac = norm_mac(mac)
        return (self.allow.get(mac) or self.block.get(mac) or {}).get("label", "")

    def as_dict(self) -> dict:
        def rows(b):
            return [{"mac": m, **v} for m, v in sorted(b.items(), key=lambda kv: -kv[1].get("added", 0))]
        return {"allow": rows(self.allow), "block": rows(self.block),
                "allow_count": len(self.allow), "block_count": len(self.block)}


# ---------------------------------------------------------------------------
# annotation + mode views
# ---------------------------------------------------------------------------


def annotate(surface: list[dict], wl: Watchlist) -> list[dict]:
    """Tag every emitter with watch status and tracker fingerprint (in place)."""
    for r in surface:
        r["watch"] = wl.status(r["addr"])
        r["watch_label"] = wl.label(r["addr"])
        tr = match_tracker(r.get("ble_hint"))
        r["tracker"] = tr["kind"] if tr else None
        r["tracker_name"] = tr["name"] if tr else None
        r["tracker_category"] = tr.get("category") if tr else None
    return surface


def _rssi_trend(series: list) -> dict:
    """Warmer / colder read from the last two sweeps, plus the latest value."""
    if not series:
        return {"delta_db": 0, "direction": "flat", "latest": None}
    latest = series[-1]
    if len(series) < 2:
        return {"delta_db": 0, "direction": "flat", "latest": latest}
    d = series[-1] - series[-2]
    return {"delta_db": d, "latest": latest,
            "direction": "warmer" if d >= 2 else "colder" if d <= -2 else "flat"}


def finder_view(surface: list[dict], include_fingerprint: bool = True) -> list[dict]:
    """FINDER: your own devices only. Allowlisted MACs, plus (optionally) any
    tracker-fingerprinted device for the rotating-MAC case. Ranked by signal."""
    hits = []
    for r in surface:
        matched_by = None
        if r.get("watch") == "allow":
            matched_by = "mac"
        elif include_fingerprint and r.get("tracker"):
            matched_by = "fingerprint"
        if matched_by:
            hits.append({**r, "matched_by": matched_by, "trend": _rssi_trend(r.get("rssi_series"))})
    hits.sort(key=lambda x: (x["rssi_median"] is None, -(x["rssi_median"] or -999)))
    return hits


def sweep_view(surface: list[dict]) -> list[dict]:
    """SWEEP (TSCM): blocklisted devices, plus any UNLISTED device that
    fingerprints as a tracker — the thing you didn't put there. Ranked by signal.

    Only LOCATORS raise the tracker flag. Pairing accessories (Fast Pair
    earbuds and the like) are returned at a separate, lower level so they can be
    shown as context rather than as an alarm.
    """
    flags = []
    for r in surface:
        level = None
        if r.get("watch") == "block":
            level = "block"
        elif r.get("watch") == "unknown" and r.get("tracker"):
            level = (
                "unknown-tracker"
                if r.get("tracker_category", "locator") == "locator"
                else "accessory"
            )
        if level:
            flags.append({**r, "flag": level, "trend": _rssi_trend(r.get("rssi_series"))})
    order = {"block": 0, "unknown-tracker": 1, "accessory": 2}
    flags.sort(key=lambda x: (order.get(x["flag"], 2), x["rssi_median"] is None, -(x["rssi_median"] or -999)))
    return flags
