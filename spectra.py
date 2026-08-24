#!/usr/bin/env python3
"""
SPECTRA — local passive RF surface inventory.

What it does:
  * Inventories Wi-Fi access points visible to your own radio, using the OS's
    native scan (no monitor mode, no injection, no association).
  * Inventories BLE advertisers in range via the host Bluetooth stack.
  * Fingerprints vendors from the OUI (first 24 bits of the MAC).
  * Tracks RSSI over repeated sweeps and reports a coarse proximity bucket
    plus a log-distance range estimate with explicit error bars.
  * Flags MAC randomization so you know which observations are NOT stable
    identifiers.
  * Ships a working k-anonymity range-query client, demonstrated against the
    HIBP Pwned Passwords API — the reference implementation of that pattern.

What it deliberately does not do:
  * No leaked-credential lookup for wireless networks. The public corpora for
    that are stale dumps and ISP default-key generators; wiring them in gets
    you a tool whose main use is opening other people's networks. The
    k-anonymity mechanism is here in full so you can study the pattern.
  * No deauth, no probe injection, no handshake capture. Receive only.

Scope note: run this against your own environment. Passive reception is
generally lawful, but sustained collection and geolocation of third-party
devices is a different activity with a different legal posture.

Install:
    pip install bleak requests        # bleak optional; Wi-Fi works without it

Usage:
    python spectra.py sweep --rounds 5 --interval 20
    python spectra.py report
    python spectra.py export --format csv --out surface.csv
    python spectra.py kanon --secret "correct horse battery staple"
    python spectra.py purge --older-than 24
    python spectra.py --db ~/.spectra/demo.db report
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import json
import math
import os
import platform
import re
import sqlite3
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

SPECTRA_HOME = Path(os.environ.get("SPECTRA_HOME", Path.home() / ".spectra"))

# Live captures and synthetic demo data live in SEPARATE databases. Seeding a
# demo into the live surface would leave fake emitters in every later report
# with no way to tell them from real ones.
LIVE_DB = SPECTRA_HOME / "surface.db"
DEMO_DB = SPECTRA_HOME / "demo.db"

DB_PATH = Path(os.environ.get("SPECTRA_DB", LIVE_DB))
OUI_CACHE = SPECTRA_HOME / "oui.json"
OUI_SOURCE = "https://standards-oui.ieee.org/oui/oui.csv"


def use_db(path) -> Path:
    """Point every later db() call at `path`. Call before opening a connection."""
    global DB_PATH
    DB_PATH = Path(path)
    return DB_PATH


# --- recency ---------------------------------------------------------------
# A surface report answers "what is around me", which is a question about NOW.
# Aggregating all history answers "what has ever been around me" and quietly
# presents week-old ghosts with a proximity bucket. Every report is therefore
# windowed. Pass window_hours=0 to deliberately aggregate everything.
DEFAULT_WINDOW_HOURS = float(os.environ.get("SPECTRA_WINDOW_HOURS", "1"))

# Inside the window, emitters heard this recently are treated as present. The
# rest are still reported, but marked stale so nothing reads as in-the-room
# when it was last heard forty minutes ago.
PRESENT_WITHIN_SECONDS = int(os.environ.get("SPECTRA_PRESENT_SECONDS", "180"))


def window_cutoff(window_hours: float | None) -> str | None:
    """ISO timestamp marking the start of the window, or None for all history."""
    if window_hours is None:
        window_hours = DEFAULT_WINDOW_HOURS
    if window_hours <= 0:
        return None
    return (
        datetime.now(timezone.utc) - timedelta(hours=window_hours)
    ).isoformat(timespec="seconds")


def _age_seconds(ts: str) -> float | None:
    try:
        seen = datetime.fromisoformat(ts)
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - seen).total_seconds())
    except Exception:
        return None

# Minimal fallback so the tool is useful before the IEEE registry is cached.
OUI_FALLBACK = {
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "00:17:88": "Signify (Philips Hue)",
    "EC:B5:FA": "Signify (Philips Hue)",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "00:0D:3A": "Microsoft",
    "7C:1E:52": "Microsoft",
    "00:03:93": "Apple",
    "AC:BC:32": "Apple",
    "F0:18:98": "Apple",
    "A4:83:E7": "Apple",
    "00:1D:D8": "Microsoft",
    "18:B4:30": "Nest Labs",
    "64:16:66": "Nest Labs",
    "44:61:32": "ecobee",
    "00:24:E4": "Withings",
    "D0:03:4B": "Apple",
    "50:32:37": "Apple",
    "C8:D0:83": "Amazon Technologies",
    "68:37:E9": "Amazon Technologies",
    "FC:65:DE": "Amazon Technologies",
    "00:1E:C0": "Microchip",
    "00:12:4B": "Texas Instruments",
    "54:6C:0E": "Texas Instruments",
    "24:0A:C4": "Espressif",
    "3C:71:BF": "Espressif",
    "84:F3:EB": "Espressif",
    "A0:20:A6": "Espressif",
    "00:1B:63": "Apple",
    "58:D9:C3": "Motorola Mobility",
    "F8:E0:79": "Motorola Mobility",
    "00:26:37": "Samsung",
    "78:1F:DB": "Samsung",
    "5C:0A:5B": "Samsung",
    "8C:83:E1": "Samsung",
    "00:1F:3B": "Intel",
    "34:13:E8": "Intel",
    "94:65:9C": "Intel",
    "00:50:F2": "Microsoft",
    "2C:30:33": "Netgear",
    "A0:40:A0": "Netgear",
    "00:14:6C": "Netgear",
    "C0:3F:0E": "Netgear",
    "00:18:4D": "Netgear",
    "B0:39:56": "Netgear",
    "00:1D:7E": "Cisco-Linksys",
    "48:F8:B3": "Cisco-Linksys",
    "00:23:69": "Cisco-Linksys",
    "14:91:82": "Belkin",
    "94:10:3E": "Belkin",
    "00:1C:DF": "Belkin",
    "D8:5D:4C": "TP-Link",
    "50:C7:BF": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "EC:08:6B": "TP-Link",
    "00:0C:42": "MikroTik",
    "48:8F:5A": "MikroTik",
    "24:5A:4C": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    "00:1A:1E": "Aruba Networks",
    "6C:F3:7F": "Aruba Networks",
    "00:0B:86": "Aruba Networks",
    "00:40:96": "Cisco",
    "00:1B:D4": "Cisco",
    "58:97:1E": "Cisco",
    "00:26:99": "Cisco",
    "E0:63:DA": "Ubiquiti",
    "00:90:4C": "Epigram/Broadcom",
    "00:9A:CD": "Huawei",
    "48:46:FB": "Huawei",
    "00:66:4B": "Huawei",
    "F4:8B:32": "Xiaomi",
    "64:CC:2E": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "00:1E:58": "D-Link",
    "1C:7E:E5": "D-Link",
    "C8:BE:19": "D-Link",
    "00:1F:1F": "Edimax",
    "00:04:ED": "Billion",
    "00:1D:0F": "TP-Link",
}

# ---------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------


@dataclass
class Observation:
    """A single sighting of a single emitter during one sweep."""

    ts: str
    band: str  # "wifi" | "ble"
    addr: str  # BSSID or BLE address, uppercase colon form
    label: str  # SSID or BLE local name; "" when hidden/absent
    rssi: int | None  # dBm; None when the OS only gave a percentage
    channel: str = ""
    security: str = ""
    vendor: str = ""
    randomized: bool = False
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# MAC helpers
# ---------------------------------------------------------------------------


def norm_mac(raw: str) -> str:
    hexs = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
    if len(hexs) != 12:
        return (raw or "").upper()
    return ":".join(hexs[i : i + 2] for i in range(0, 12, 2)).upper()


def is_randomized(mac: str) -> bool:
    """Locally-administered bit set in the first octet => randomized/private.

    This is the single most important signal in the whole tool. If it is True,
    the address is not a durable identifier and any cross-session tracking or
    vendor attribution built on it is fiction.
    """
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0b10)


def load_oui() -> dict[str, str]:
    if OUI_CACHE.exists():
        try:
            return json.loads(OUI_CACHE.read_text())
        except Exception:
            pass
    return dict(OUI_FALLBACK)


def refresh_oui() -> int:
    """Pull the IEEE MA-L registry and cache it. Run once; it changes slowly."""
    try:
        import requests
    except ImportError:
        print("refresh-oui needs: pip install requests", file=sys.stderr)
        return 0
    print(f"fetching {OUI_SOURCE} ...")
    resp = requests.get(OUI_SOURCE, timeout=60)
    resp.raise_for_status()
    table: dict[str, str] = {}
    reader = csv.DictReader(resp.text.splitlines())
    for row in reader:
        assign = (row.get("Assignment") or "").strip().upper()
        org = (row.get("Organization Name") or "").strip()
        if len(assign) == 6 and org:
            table[":".join(assign[i : i + 2] for i in range(0, 6, 2))] = org
    OUI_CACHE.parent.mkdir(parents=True, exist_ok=True)
    OUI_CACHE.write_text(json.dumps(table))
    print(f"cached {len(table)} OUI entries -> {OUI_CACHE}")
    return len(table)


def vendor_for(mac: str, table: dict[str, str]) -> str:
    if is_randomized(mac):
        return "(randomized — no vendor)"
    return table.get(mac[:8], "")


# ---------------------------------------------------------------------------
# distance estimation
# ---------------------------------------------------------------------------


def estimate_range(rssi: float, tx_power: float = -45.0, path_loss_n: float = 2.7):
    """Log-distance path loss. Returns (metres, low, high).

    d = 10 ** ((TxPower - RSSI) / (10 * n))

    The error bars are not decoration. Indoor n varies from about 2.0 in open
    space to 4.0 through walls, and TxPower differs per device, so the honest
    output is an order-of-magnitude bucket. Anything claiming metre-accurate
    positioning from bare RSSI is overselling.
    """
    if rssi is None:
        return (None, None, None)
    def d(n: float) -> float:
        return 10 ** ((tx_power - rssi) / (10 * n))
    return (round(d(path_loss_n), 1), round(d(4.0), 1), round(d(2.0), 1))


def proximity_bucket(rssi: float | None) -> str:
    if rssi is None:
        return "unknown"
    if rssi >= -50:
        return "immediate (<2m)"
    if rssi >= -65:
        return "near (2-8m)"
    if rssi >= -80:
        return "mid (8-25m)"
    return "far (>25m)"


# ---------------------------------------------------------------------------
# Wi-Fi scanning — OS native, receive only
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 45) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout or ""
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return ""


def scan_wifi_windows() -> list[Observation]:
    text = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    obs: list[Observation] = []
    ssid = ""
    security = ""
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            ssid = m.group(1).strip()
            security = ""
            continue
        m = re.match(r"^Authentication\s*:\s*(.*)$", line)
        if m:
            security = m.group(1).strip()
            continue
        m = re.match(r"^BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})", line)
        if m:
            obs.append(
                Observation(
                    ts=now_iso(),
                    band="wifi",
                    addr=norm_mac(m.group(1)),
                    label=ssid,
                    rssi=None,
                    security=security,
                )
            )
            continue
        m = re.match(r"^Signal\s*:\s*(\d+)%", line)
        if m and obs:
            pct = int(m.group(1))
            # netsh reports quality percent, not dBm. This is the standard
            # linear mapping Microsoft documents; treat it as approximate.
            obs[-1].rssi = int(pct / 2) - 100
            continue
        m = re.match(r"^Channel\s*:\s*(\S+)", line)
        if m and obs:
            obs[-1].channel = m.group(1)
    return obs


def scan_wifi_linux() -> list[Observation]:
    text = _run(
        ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list",
         "--rescan", "yes"]
    )
    obs: list[Observation] = []
    for line in text.splitlines():
        # nmcli escapes field-internal colons as \: and also escapes spaces,
        # backslashes and its own delimiter inside SSIDs. Split on unescaped
        # colons, then unescape every remaining backslash pair.
        parts = re.split(r"(?<!\\):", line)
        parts = [re.sub(r"\\(.)", r"\1", p) for p in parts]
        if len(parts) < 5:
            continue
        ssid, bssid, signal, chan, sec = parts[0], parts[1], parts[2], parts[3], parts[4]
        try:
            pct = int(signal)
        except ValueError:
            pct = 0
        obs.append(
            Observation(
                ts=now_iso(),
                band="wifi",
                addr=norm_mac(bssid),
                label=ssid,
                rssi=int(pct / 2) - 100,
                channel=chan,
                security=sec,
            )
        )
    return obs


def scan_wifi_macos() -> list[Observation]:
    # The airport binary was removed in Sonoma; system_profiler still works.
    text = _run(["system_profiler", "-json", "SPAirPortDataType"])
    obs: list[Observation] = []
    if not text:
        return obs
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return obs

    def walk(node):
        if isinstance(node, dict):
            if "_name" in node and "spairport_signal_noise" in node:
                sig = node.get("spairport_signal_noise", "")
                m = re.search(r"(-?\d+)\s*dBm", sig)
                obs.append(
                    Observation(
                        ts=now_iso(),
                        band="wifi",
                        addr=norm_mac(node.get("spairport_bssid", "")),
                        label=node.get("_name", ""),
                        rssi=int(m.group(1)) if m else None,
                        channel=str(node.get("spairport_network_channel", "")),
                        security=str(node.get("spairport_security_mode", "")),
                    )
                )
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)

    if not obs:
        # macOS Sonoma and later redact scan results unless the calling process
        # holds Location Services permission. Silently returning an empty list
        # here reads to the user as "no Wi-Fi in range", which sends them
        # hunting a hardware problem that does not exist.
        print(
            "  NOTE: macOS returned no Wi-Fi scan results.\n"
            "  Since Sonoma this usually means Location Services permission, not a\n"
            "  radio problem. System Settings > Privacy & Security > Location\n"
            "  Services, enable it for Terminal (or your Python/IDE), then rerun.",
            file=sys.stderr,
        )
    return obs


def scan_wifi() -> list[Observation]:
    system = platform.system()
    if system == "Windows":
        return scan_wifi_windows()
    if system == "Linux":
        return scan_wifi_linux()
    if system == "Darwin":
        return scan_wifi_macos()
    return []


# ---------------------------------------------------------------------------
# BLE scanning — host stack, advertisement packets only
# ---------------------------------------------------------------------------


async def _scan_ble_async(seconds: float) -> list[Observation]:
    try:
        from bleak import BleakScanner
    except ImportError:
        print("BLE skipped (pip install bleak)", file=sys.stderr)
        return []

    obs: list[Observation] = []
    try:
        # Overall cap: discover() should return after `seconds`, but a wedged
        # or absent adapter can leave the backend awaiting a D-Bus reply that
        # never comes. The outer wait_for guarantees the call returns.
        found = await asyncio.wait_for(
            BleakScanner.discover(timeout=seconds, return_adv=True),
            timeout=seconds + 4,
        )
    except asyncio.TimeoutError:
        print("BLE scan timed out (adapter unresponsive)", file=sys.stderr)
        return []
    except Exception as exc:  # no adapter, adapter off, permissions
        print(f"BLE unavailable: {exc}", file=sys.stderr)
        return []

    for _, (device, adv) in found.items():
        mfr = {}
        for cid, payload in (adv.manufacturer_data or {}).items():
            mfr[str(cid)] = payload.hex()
        obs.append(
            Observation(
                ts=now_iso(),
                band="ble",
                addr=norm_mac(device.address),
                label=(adv.local_name or "") if adv else "",
                rssi=adv.rssi if adv else None,
                extra={
                    "services": list(adv.service_uuids or []),
                    "manufacturer_data": mfr,
                    "tx_power": adv.tx_power,
                },
            )
        )
    return obs


def scan_ble(seconds: float = 8.0) -> list[Observation]:
    try:
        return asyncio.run(_scan_ble_async(seconds))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_scan_ble_async(seconds))
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            band TEXT NOT NULL,
            addr TEXT NOT NULL,
            label TEXT,
            rssi INTEGER,
            channel TEXT,
            security TEXT,
            vendor TEXT,
            randomized INTEGER,
            extra TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_addr ON observations(addr)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON observations(ts)")
    conn.commit()
    return conn


def persist(conn: sqlite3.Connection, rows: Iterable[Observation]) -> int:
    n = 0
    for o in rows:
        conn.execute(
            "INSERT INTO observations (ts,band,addr,label,rssi,channel,security,"
            "vendor,randomized,extra) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                o.ts, o.band, o.addr, o.label, o.rssi, o.channel, o.security,
                o.vendor, int(o.randomized), json.dumps(o.extra),
            ),
        )
        n += 1
    conn.commit()
    return n


# ---------------------------------------------------------------------------
# k-anonymity range query
# ---------------------------------------------------------------------------


def kanon_lookup(secret: str, prefix_len: int = 5) -> dict:
    """Range query against HIBP Pwned Passwords.

    The whole trick: SHA-1 the secret, send only the first `prefix_len` hex
    characters, receive every suffix sharing that prefix, and compare locally.
    The server learns you asked about one of roughly 400-800 candidates and
    never learns which. That's the k in k-anonymity — your query is
    indistinguishable from k-1 others.

    The same construction is sometimes claimed for wireless credential lookups.
    Implementing it here, against the one public API that genuinely provides it,
    demonstrates the mechanism without needing a credential corpus of any kind —
    and SPECTRA deliberately does not ship one.
    """
    try:
        import requests
    except ImportError:
        return {"error": "pip install requests"}

    digest = hashlib.sha1(secret.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:prefix_len], digest[prefix_len:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"User-Agent": "spectra-local-lab"},
            timeout=30,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {
            "error": f"couldn't reach the range API ({exc.__class__.__name__})",
            "prefix_sent": prefix,
            "hint": "check network access to api.pwnedpasswords.com",
        }

    bucket = {}
    for line in resp.text.splitlines():
        if ":" in line:
            suf, count = line.split(":", 1)
            bucket[suf.strip()] = int(count.strip().replace(",", ""))

    return {
        "prefix_sent": prefix,
        "digest_withheld": True,
        "bucket_size_k": len(bucket),
        "found": suffix in bucket,
        "occurrences": bucket.get(suffix, 0),
        "bytes_leaked_to_server": len(prefix) * 4 // 8,
    }


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def prune(conn: sqlite3.Connection, retain_hours: float) -> int:
    """Delete observations older than `retain_hours`. Returns rows removed.

    Retention is a control, not housekeeping. This database accumulates a record
    of every wireless device in range, including other people's, and a tool that
    keeps that forever by default is making a decision on the operator's behalf.
    """
    if retain_hours is None or retain_hours <= 0:
        return 0
    cutoff = (
        datetime.now(timezone.utc) - timedelta(hours=retain_hours)
    ).isoformat(timespec="seconds")
    cur = conn.execute("DELETE FROM observations WHERE ts < ?", (cutoff,))
    conn.commit()
    return cur.rowcount or 0


def build_report(
    conn: sqlite3.Connection, window_hours: float | None = None
) -> list[dict]:
    """Aggregate observations into a current surface.

    window_hours: None uses DEFAULT_WINDOW_HOURS; 0 or less aggregates all
    history (the old behaviour, useful for forensics, wrong for a live console).
    """
    cutoff = window_cutoff(window_hours)
    if cutoff:
        cur = conn.execute(
            "SELECT addr, band, label, vendor, randomized, channel, security, rssi, ts, extra "
            "FROM observations WHERE ts >= ? ORDER BY ts",
            (cutoff,),
        )
    else:
        cur = conn.execute(
            "SELECT addr, band, label, vendor, randomized, channel, security, rssi, ts, extra "
            "FROM observations ORDER BY ts"
        )
    agg: dict[str, dict] = {}
    for addr, band, label, vendor, rand, chan, sec, rssi, ts, extra in cur:
        e = agg.setdefault(
            addr,
            {
                "addr": addr, "band": band, "labels": set(), "vendor": vendor or "",
                "randomized": bool(rand), "channel": chan or "", "security": sec or "",
                "rssi": [], "series": [], "first_seen": ts, "last_seen": ts,
                "sightings": 0, "extra": None,
            },
        )
        if label:
            e["labels"].add(label)
        # Rows arrive in ts order, so the last non-empty value wins. An AP that
        # changes channel, or whose first sighting had an empty field, is now
        # reported as it currently is rather than as it first appeared.
        if chan:
            e["channel"] = chan
        if sec:
            e["security"] = sec
        if vendor:
            e["vendor"] = vendor
        if rssi is not None:
            e["rssi"].append(rssi)
            e["series"].append((ts, rssi))
        if extra:
            e["extra"] = extra  # keep the most recent advertisement payload
        e["last_seen"] = ts
        e["sightings"] += 1

    out = []
    for e in agg.values():
        samples = e["rssi"]
        med = statistics.median(samples) if samples else None
        spread = (
            round(statistics.pstdev(samples), 1) if len(samples) > 1 else 0.0
        )
        dist, lo, hi = estimate_range(med) if med is not None else (None, None, None)
        series = [rssi for _, rssi in sorted(e["series"], key=lambda p: p[0])]
        age = _age_seconds(e["last_seen"])

        ble_hint = None
        if e["band"] == "ble" and e.get("extra"):
            try:
                import spectra_rf  # optional; suite module
                extra = json.loads(e["extra"]) if isinstance(e["extra"], str) else e["extra"]
                cls = spectra_rf.classify_ble(
                    extra.get("manufacturer_data"),
                    extra.get("services"),
                    " / ".join(sorted(e["labels"])),
                )
                ble_hint = cls.get("summary")
            except Exception:
                ble_hint = None

        out.append(
            {
                "addr": e["addr"],
                "rssi_series": series,
                "band": e["band"],
                "label": " / ".join(sorted(e["labels"])) or "(hidden or unnamed)",
                "vendor": e["vendor"],
                "randomized": e["randomized"],
                "channel": e["channel"],
                "security": e["security"],
                "sightings": e["sightings"],
                "rssi_median": med,
                "rssi_stdev": spread,
                "proximity": proximity_bucket(med),
                "range_m": dist,
                "range_low_m": lo,
                "range_high_m": hi,
                "stable_identifier": not e["randomized"],
                "ble_hint": ble_hint,
                "first_seen": e["first_seen"],
                "last_seen": e["last_seen"],
                "age_seconds": age,
                "present": (age is not None and age <= PRESENT_WITHIN_SECONDS),
            }
        )
    out.sort(key=lambda r: (r["rssi_median"] is None, -(r["rssi_median"] or -999)))
    return out


def print_report(rows: list[dict], window_hours: float | None = None) -> None:
    if not rows:
        if window_cutoff(window_hours):
            hrs = DEFAULT_WINDOW_HOURS if window_hours is None else window_hours
            print(f"Nothing heard in the last {hrs:g}h. Run: python spectra.py sweep")
            print("(--window 0 reports all stored history instead)")
        else:
            print("No observations yet. Run: python spectra.py sweep")
        return

    wifi = [r for r in rows if r["band"] == "wifi"]
    ble = [r for r in rows if r["band"] == "ble"]
    rand = [r for r in rows if r["randomized"]]

    stale = [r for r in rows if not r.get("present", True)]
    hrs = DEFAULT_WINDOW_HOURS if window_hours is None else window_hours
    scope = f"last {hrs:g}h" if window_cutoff(window_hours) else "ALL history"

    print(f"\n{'=' * 78}")
    print(f"  SPECTRA surface report — {len(rows)} distinct emitters ({scope})")
    print(f"  {len(wifi)} Wi-Fi  |  {len(ble)} BLE  |  "
          f"{len(rand)} randomized (untrackable across sessions)")
    if stale:
        print(f"  {len(stale)} not heard in the last "
              f"{PRESENT_WITHIN_SECONDS // 60}m — marked STALE, may have left")
    print(f"{'=' * 78}")

    for band, group in (("WI-FI ACCESS POINTS", wifi), ("BLE ADVERTISERS", ble)):
        if not group:
            continue
        print(f"\n{band}")
        print("-" * 78)
        for r in group:
            flag = " [RND]" if r["randomized"] else ""
            if not r.get("present", True):
                flag += " [STALE]"
            rssi = f"{r['rssi_median']:>5.0f} dBm" if r["rssi_median"] is not None else "   n/a  "
            print(f"  {r['addr']}{flag}  {rssi}  ±{r['rssi_stdev']:<4}  {r['proximity']}")
            print(f"    label   : {r['label']}")
            if r["vendor"]:
                print(f"    vendor  : {r['vendor']}")
            if r["security"]:
                print(f"    security: {r['security']}  ch {r['channel']}")
            if r["range_m"] is not None:
                print(f"    range   : ~{r['range_m']}m  (plausible {r['range_low_m']}–{r['range_high_m']}m)")
            print(f"    seen    : {r['sightings']}x  {r['first_seen']} → {r['last_seen']}")
            print()

    if rand:
        print("-" * 78)
        plural = "emitter uses" if len(rand) == 1 else "emitters use"
        print(f"  NOTE: {len(rand)} {plural} randomized addresses. Those rotate")
        print("  on a schedule set by the OS, so counting them as distinct devices")
        print("  overcounts, and correlating them across sweeps is unsound.")
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def cmd_sweep(args) -> None:
    oui = load_oui()
    conn = db()
    total = 0
    for i in range(args.rounds):
        batch: list[Observation] = []
        if not args.ble_only:
            batch.extend(scan_wifi())
        if not args.wifi_only:
            batch.extend(scan_ble(args.ble_seconds))
        for o in batch:
            o.vendor = vendor_for(o.addr, oui)
            o.randomized = is_randomized(o.addr)
        total += persist(conn, batch)
        print(f"  sweep {i + 1}/{args.rounds}: {len(batch)} observations")
        if i < args.rounds - 1:
            time.sleep(args.interval)
    conn.close()
    print(f"\n{total} observations stored -> {DB_PATH}")
    if total == 0:
        print("Nothing captured. Check: Wi-Fi radio on, Bluetooth on, "
              "and on Linux that nmcli is present.")


def cmd_report(args) -> None:
    conn = db()
    w = getattr(args, "window", None)
    print_report(build_report(conn, window_hours=w), window_hours=w)
    conn.close()


def cmd_export(args) -> None:
    conn = db()
    rows = build_report(conn, window_hours=getattr(args, "window", None))
    conn.close()
    out = Path(args.out)
    if args.format == "json":
        out.write_text(json.dumps(rows, indent=2))
    else:
        if not rows:
            print("nothing to export")
            return
        with out.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {out}")


def cmd_kanon(args) -> None:
    result = kanon_lookup(args.secret, args.prefix_len)
    print(json.dumps(result, indent=2))
    if result.get("bucket_size_k"):
        print(f"\nThe server saw only '{result['prefix_sent']}' and returned "
              f"{result['bucket_size_k']} candidate hashes.")
        print("Your specific query is hidden among those. That is the mechanism.")


def cmd_refresh_oui(args) -> None:
    refresh_oui()


def cmd_purge(args) -> None:
    """Delete stored observations. Whole DB, or everything older than N hours.

    Reports are windowed, so old rows no longer pollute the surface — but they
    still occupy the database. Purge to reclaim space or to hand off a clean run.
    """
    conn = db()
    try:
        if args.older_than:
            cutoff = (
                datetime.now(timezone.utc) - timedelta(hours=args.older_than)
            ).isoformat(timespec="seconds")
            total = conn.execute(
                "SELECT COUNT(*) FROM observations WHERE ts < ?", (cutoff,)
            ).fetchone()[0]
            scope = f"{total} observation(s) older than {args.older_than}h"
        else:
            total = conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0]
            scope = f"all {total} observation(s)"

        if total == 0:
            print(f"nothing to delete in {DB_PATH}")
            return

        if not args.yes and sys.stdin.isatty():
            reply = input(f"Delete {scope} from {DB_PATH}? [y/N] ").strip().lower()
            if reply not in ("y", "yes"):
                print("aborted")
                return

        if args.older_than:
            conn.execute("DELETE FROM observations WHERE ts < ?", (cutoff,))
        else:
            conn.execute("DELETE FROM observations")
        conn.commit()
        conn.execute("VACUUM")
        print(f"deleted {scope} -> {DB_PATH}")
    finally:
        conn.close()


def main() -> None:
    p = argparse.ArgumentParser(
        prog="spectra", description="Local passive RF surface inventory."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("sweep", help="collect observations")
    s.add_argument("--rounds", type=int, default=3)
    s.add_argument("--interval", type=int, default=15, help="seconds between rounds")
    s.add_argument("--ble-seconds", type=float, default=8.0)
    s.add_argument("--wifi-only", action="store_true")
    s.add_argument("--ble-only", action="store_true")
    s.set_defaults(func=cmd_sweep)

    r = sub.add_parser("report", help="summarize what has been seen")
    r.set_defaults(func=cmd_report)

    e = sub.add_parser("export", help="write csv/json")
    e.add_argument("--format", choices=["csv", "json"], default="csv")
    e.add_argument("--out", default="spectra_surface.csv")
    e.set_defaults(func=cmd_export)

    k = sub.add_parser("kanon", help="k-anonymity range query demo")
    k.add_argument("--secret", required=True)
    k.add_argument("--prefix-len", type=int, default=5)
    k.set_defaults(func=cmd_kanon)

    o = sub.add_parser("refresh-oui", help="cache the IEEE OUI registry")
    o.set_defaults(func=cmd_refresh_oui)

    g = sub.add_parser("purge", help="delete stored observations")
    g.add_argument("--older-than", type=float, metavar="HOURS",
                   help="only delete observations older than this many hours")
    g.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    g.set_defaults(func=cmd_purge)

    p.add_argument("--db", metavar="PATH",
                   help="use this database instead of the default live surface")
    p.add_argument("--window", type=float, metavar="HOURS", default=None,
                   help=f"only aggregate the last N hours "
                        f"(default {DEFAULT_WINDOW_HOURS:g}; 0 = all history)")

    args = p.parse_args()
    if getattr(args, "db", None):
        use_db(args.db)
    args.func(args)


if __name__ == "__main__":
    main()
