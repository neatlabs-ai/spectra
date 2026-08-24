#!/usr/bin/env python3
"""
SPECTRA RF — wideband spectrum scanning and signal identification.

This is the module that reaches past Wi-Fi/BLE into the actual radio spectrum,
IF you have a Software Defined Radio attached. It shells out to the standard
librtlsdr / hackrf command-line tools, parses their power sweeps, finds peaks
above the noise floor, and identifies each one against a US band plan.

Hardware reality (stated plainly so nobody is misled):
  * A laptop's built-in Wi-Fi/BLE radios CANNOT do this. They demodulate two
    narrow protocol bands and nothing else.
  * RTL-SDR (~$30, RTL2832U): ~24 MHz - 1.766 GHz. Sees FM, airband, weather,
    VHF/UHF TV broadcast, 315/433/915 MHz ISM, pagers, ADS-B, GPS L1. Does NOT
    reach 2.4 GHz Wi-Fi.
  * HackRF / Airspy: 1 MHz - 6 GHz. Reaches the Wi-Fi bands too.

Scanning is receive-only. Nothing here transmits.

If no SDR is present, scan() returns a clear capability message, and simulate()
produces a realistic synthetic spectrum so the UI is usable without hardware.
"""

from __future__ import annotations

import math
import random
import shutil
import subprocess
from dataclasses import dataclass, asdict, field
from typing import Any

MHZ = 1_000_000


# ---------------------------------------------------------------------------
# US band plan  (lo_mhz, hi_mhz, label, category)
# Categories drive colour in the UI: broadcast, aero, ham, ism, cellular,
# pubsafety, satnav, weather, tv, marine, radar, other
# ---------------------------------------------------------------------------

BAND_PLAN: list[tuple[float, float, str, str]] = [
    (0.535, 1.705, "AM broadcast", "broadcast"),
    (1.8, 2.0, "160m amateur", "ham"),
    (3.5, 4.0, "80m amateur", "ham"),
    (5.9, 6.2, "49m shortwave", "broadcast"),
    (7.0, 7.3, "40m amateur", "ham"),
    (14.0, 14.35, "20m amateur", "ham"),
    (26.965, 27.405, "CB radio", "other"),
    (28.0, 29.7, "10m amateur", "ham"),
    (50.0, 54.0, "6m amateur", "ham"),
    (88.0, 108.0, "FM broadcast", "broadcast"),
    (108.0, 118.0, "Aeronautical nav (VOR/ILS)", "aero"),
    (118.0, 137.0, "Airband (AM voice)", "aero"),
    (137.0, 138.0, "Weather satellite (NOAA APT)", "weather"),
    (144.0, 148.0, "2m amateur", "ham"),
    (148.0, 150.0, "Satellite / military", "other"),
    (156.0, 162.025, "Marine VHF", "marine"),
    (162.4, 162.55, "NOAA weather radio", "weather"),
    (162.55, 174.0, "VHF business / public safety", "pubsafety"),
    (174.0, 216.0, "VHF TV (ch 7-13) / DAB", "tv"),
    (225.0, 400.0, "Military UHF air", "aero"),
    (314.0, 316.0, "ISM 315 - key fobs / TPMS", "ism"),
    (400.15, 401.0, "Weather balloon / radiosonde", "weather"),
    (420.0, 450.0, "70cm amateur", "ham"),
    (433.05, 434.79, "ISM 433 - remotes / sensors", "ism"),
    (450.0, 470.0, "UHF business / public safety", "pubsafety"),
    (470.0, 608.0, "UHF TV broadcast (ch 14-36)", "tv"),
    (608.0, 614.0, "Radio astronomy", "other"),
    (614.0, 698.0, "UHF TV / 600 MHz 5G", "tv"),
    (698.0, 758.0, "700 MHz LTE (lower)", "cellular"),
    (758.0, 806.0, "700 MHz LTE (upper) / FirstNet", "pubsafety"),
    (806.0, 824.0, "800 MHz public safety / SMR", "pubsafety"),
    (824.0, 849.0, "Cellular 850 uplink", "cellular"),
    (851.0, 869.0, "800 MHz public safety", "pubsafety"),
    (869.0, 894.0, "Cellular 850 downlink", "cellular"),
    (902.0, 928.0, "ISM 915 - IoT / LoRa / cordless", "ism"),
    (928.0, 932.0, "Paging / fixed data", "other"),
    (935.0, 941.0, "Paging", "other"),
    (960.0, 1164.0, "Aeronautical (DME / TACAN)", "aero"),
    (1030.0, 1030.0, "Secondary radar interrogation", "radar"),
    (1090.0, 1090.0, "ADS-B (aircraft transponders)", "aero"),
    (1176.45, 1176.45, "GPS L5", "satnav"),
    (1227.6, 1227.6, "GPS L2", "satnav"),
    (1240.0, 1300.0, "23cm amateur / radar", "ham"),
    (1525.0, 1559.0, "Inmarsat / MSS downlink", "satnav"),
    (1559.0, 1610.0, "GNSS (GPS L1 1575.42)", "satnav"),
    (1710.0, 1780.0, "AWS-1/3 cellular uplink", "cellular"),
    (1850.0, 1915.0, "PCS cellular uplink", "cellular"),
    (1930.0, 1995.0, "PCS cellular downlink", "cellular"),
    (2110.0, 2200.0, "AWS / UMTS downlink", "cellular"),
    (2300.0, 2360.0, "WCS / satellite radio", "cellular"),
    (2400.0, 2483.5, "ISM 2.4 GHz - Wi-Fi / BLE / Zigbee", "ism"),
    (2500.0, 2690.0, "BRS/EBS 2.5 GHz 5G", "cellular"),
    (3550.0, 3700.0, "CBRS 3.5 GHz", "cellular"),
    (3700.0, 3980.0, "C-band 5G", "cellular"),
    (5150.0, 5895.0, "U-NII Wi-Fi 5/6 / DSRC", "ism"),
]


def identify_frequency(hz: float) -> dict[str, str]:
    """Return the band-plan entry a frequency falls in.

    Point services (ADS-B, GPS) match first within a small guard. Otherwise the
    *narrowest* containing band wins, so a 433.92 MHz fob reads as 'ISM 433'
    rather than the wider '70cm amateur' allocation it also sits inside.
    """
    mhz = hz / MHZ
    for lo, hi, label, cat in BAND_PLAN:
        if lo == hi and abs(mhz - lo) <= 0.5:
            return {"label": label, "category": cat, "band": f"{lo:g} MHz"}
    matches = [(hi - lo, lo, hi, label, cat) for lo, hi, label, cat in BAND_PLAN
               if lo != hi and lo <= mhz <= hi]
    if matches:
        _, lo, hi, label, cat = min(matches, key=lambda m: m[0])
        return {"label": label, "category": cat, "band": f"{lo:g}-{hi:g} MHz"}
    return {"label": "unallocated / unknown", "category": "other", "band": f"{mhz:.3f} MHz"}


# ---------------------------------------------------------------------------
# scan presets
# ---------------------------------------------------------------------------

PRESETS: dict[str, dict[str, Any]] = {
    "fm":       {"lo": 88.0,   "hi": 108.0,  "bin_khz": 50,  "title": "FM broadcast"},
    "airband":  {"lo": 118.0,  "hi": 137.0,  "bin_khz": 25,  "title": "Airband"},
    "weather":  {"lo": 162.0,  "hi": 163.0,  "bin_khz": 12.5,"title": "NOAA weather"},
    "vhf-tv":   {"lo": 174.0,  "hi": 216.0,  "bin_khz": 100, "title": "VHF TV"},
    "ism-315":  {"lo": 314.0,  "hi": 316.0,  "bin_khz": 10,  "title": "ISM 315 (fobs)"},
    "ism-433":  {"lo": 433.0,  "hi": 435.0,  "bin_khz": 10,  "title": "ISM 433 (sensors)"},
    "uhf-tv":   {"lo": 470.0,  "hi": 698.0,  "bin_khz": 250, "title": "UHF TV broadcast"},
    "ism-915":  {"lo": 902.0,  "hi": 928.0,  "bin_khz": 50,  "title": "ISM 915 (IoT)"},
    "adsb":     {"lo": 1089.0, "hi": 1091.0, "bin_khz": 25,  "title": "ADS-B aircraft"},
    "gps":      {"lo": 1574.0, "hi": 1577.0, "bin_khz": 25,  "title": "GPS L1"},
    "full-low": {"lo": 24.0,   "hi": 1000.0, "bin_khz": 1000,"title": "Wideband survey"},
}


# ---------------------------------------------------------------------------
# SDR detection
# ---------------------------------------------------------------------------


def detect_sdr() -> dict[str, Any]:
    """What SDR tooling is on PATH, and what it can cover."""
    rtl = shutil.which("rtl_power")
    hackrf = shutil.which("hackrf_sweep")
    airspy = shutil.which("airspy_rx")
    tool = None
    coverage = None
    # Prefer a backend that is actually IMPLEMENTED. hackrf_sweep covers more
    # spectrum, but only the rtl_power CSV parser is wired up, so preferring
    # HackRF meant that owning the better radio produced a hard failure while a
    # $30 dongle worked. Detect it, report it, do not select it.
    if rtl:
        tool, coverage = "rtl_power", "24 MHz - 1.766 GHz"
    elif hackrf:
        tool, coverage = "hackrf_sweep", "1 MHz - 6 GHz"
    elif airspy:
        tool, coverage = "airspy", "24 MHz - 1.8 GHz"
    return {
        "available": tool is not None,
        "tool": tool,
        "coverage": coverage,
        "found": {"rtl_power": bool(rtl), "hackrf_sweep": bool(hackrf), "airspy_rx": bool(airspy)},
        "note": (
            f"{tool} detected — spectrum scanning live ({coverage})."
            + (
                "  (hackrf_sweep is also present but its parser is not wired yet,"
                " so rtl_power is being used.)"
                if tool == "rtl_power" and hackrf
                else ""
            )
            if tool
            else "No SDR tool on PATH. Add an RTL-SDR (~$30) and install rtl-sdr, "
                 "or use simulation mode to preview."
        ),
    }


# ---------------------------------------------------------------------------
# rtl_power CSV parsing
# ---------------------------------------------------------------------------


def parse_rtl_power(text: str) -> list[tuple[float, float]]:
    """rtl_power CSV -> [(freq_hz, power_db), ...].

    Row format: date, time, Hz_low, Hz_high, Hz_step, samples, dB, dB, ...
    Each dB value is one bin starting at Hz_low + i*Hz_step.
    """
    bins: list[tuple[float, float]] = []
    for line in text.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 7:
            continue
        try:
            lo = float(parts[2]); step = float(parts[4])
            powers = [float(p) for p in parts[6:] if p not in ("", "-inf", "nan")]
        except ValueError:
            continue
        for i, p in enumerate(powers):
            bins.append((lo + i * step, p))
    bins.sort(key=lambda b: b[0])
    return bins


# ---------------------------------------------------------------------------
# peak detection + classification
# ---------------------------------------------------------------------------


def _noise_floor(powers: list[float]) -> float:
    if not powers:
        return -100.0
    s = sorted(powers)
    return s[len(s) // 2]  # median as a robust floor


def find_peaks(bins: list[tuple[float, float]], margin_db: float = 6.0,
               gap_bins: int = 3) -> dict:
    """Bins above (noise floor + margin), merged into discrete peaks.

    Contiguity is tracked in bin steps: a run of bins stays one peak until more
    than `gap_bins` consecutive bins fall back under threshold. This collapses a
    wide TV/cellular carrier (many adjacent hot bins) into a single labeled peak
    instead of hundreds.
    """
    if not bins:
        return {"noise_floor_db": -100.0, "peaks": []}
    step = (bins[1][0] - bins[0][0]) if len(bins) > 1 else 1.0
    floor = _noise_floor([p for _, p in bins])
    thresh = floor + margin_db
    peaks: list[dict] = []
    current: list[tuple[float, float]] = []
    gap = 0

    def flush():
        if current:
            f, p = max(current, key=lambda x: x[1])
            width_mhz = round((current[-1][0] - current[0][0]) / MHZ, 3)
            peaks.append({"freq_hz": f, "power_db": round(p, 1),
                          "snr_db": round(p - floor, 1), "width_mhz": width_mhz})

    for freq, power in bins:
        if power >= thresh:
            current.append((freq, power)); gap = 0
        else:
            if current:
                gap += 1
                if gap > gap_bins:
                    flush(); current = []; gap = 0
    flush()

    for pk in peaks:
        pk.update(identify_frequency(pk["freq_hz"]))
        pk["freq_mhz"] = round(pk["freq_hz"] / MHZ, 4)
    peaks.sort(key=lambda x: -x["power_db"])
    return {"noise_floor_db": round(floor, 1), "peaks": peaks}


# ---------------------------------------------------------------------------
# live scan
# ---------------------------------------------------------------------------


def scan(lo_mhz: float, hi_mhz: float, bin_khz: float = 100,
         integration_s: int = 1) -> dict[str, Any]:
    """Run a real sweep if an SDR tool is present."""
    sdr = detect_sdr()
    if not sdr["available"]:
        return {"ok": False, "reason": "no_sdr", "sdr": sdr}

    if sdr["tool"] == "rtl_power":
        cmd = ["rtl_power", "-f", f"{lo_mhz}M:{hi_mhz}M:{bin_khz}k",
               "-i", str(integration_s), "-1", "-"]
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=integration_s + 30, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            return {"ok": False, "reason": f"scan_failed: {exc.__class__.__name__}", "sdr": sdr}
        bins = parse_rtl_power(out.stdout)
        result = find_peaks(bins)
        return {"ok": True, "sdr": sdr, "bins": bins, "spectrum": _downsample(bins),
                "noise_floor_db": result["noise_floor_db"], "peaks": result["peaks"],
                "range": {"lo_mhz": lo_mhz, "hi_mhz": hi_mhz, "bin_khz": bin_khz}}

    # hackrf_sweep parser differs; keep the door open, degrade for now
    return {"ok": False, "reason": f"{sdr['tool']}_not_wired", "sdr": sdr}


def scan_preset(name: str, **over) -> dict[str, Any]:
    p = PRESETS.get(name)
    if not p:
        return {"ok": False, "reason": "unknown_preset"}
    return scan(over.get("lo", p["lo"]), over.get("hi", p["hi"]), over.get("bin_khz", p["bin_khz"]))


def _downsample(bins: list[tuple[float, float]], target: int = 480) -> list[list[float]]:
    """Thin a dense sweep for plotting: [[freq_mhz, power_db], ...]."""
    if len(bins) <= target:
        return [[round(f / MHZ, 4), round(p, 1)] for f, p in bins]
    stride = len(bins) / target
    out = []
    for i in range(target):
        f, p = bins[int(i * stride)]
        out.append([round(f / MHZ, 4), round(p, 1)])
    return out


# ---------------------------------------------------------------------------
# simulation — realistic synthetic spectrum for demo / no-hardware preview
# ---------------------------------------------------------------------------


def simulate(lo_mhz: float, hi_mhz: float, bin_khz: float = 100) -> dict[str, Any]:
    """Synthesize a plausible spectrum: noise floor + carriers where the band
    plan says real services live, so the waterfall and peak-ID look authentic."""
    step_hz = bin_khz * 1000
    n = max(16, int((hi_mhz - lo_mhz) * MHZ / step_hz))
    bins: list[tuple[float, float]] = []
    floor = -78 + random.uniform(-2, 2)

    # seed a few carriers from band-plan services intersecting the window
    carriers: list[tuple[float, float, float]] = []  # (mhz, strength, width_mhz)
    for lo, hi, label, cat in BAND_PLAN:
        c = (lo + hi) / 2
        if lo_mhz <= c <= hi_mhz:
            if cat == "broadcast" and "FM" in label:
                for _ in range(random.randint(3, 7)):
                    carriers.append((random.uniform(lo_mhz, hi_mhz), random.uniform(25, 45), 0.15))
            elif cat == "tv":
                for _ in range(random.randint(2, 5)):
                    carriers.append((random.uniform(max(lo, lo_mhz), min(hi, hi_mhz)), random.uniform(18, 35), 6.0))
            elif cat == "aero" and "ADS-B" in label:
                carriers.append((1090.0, random.uniform(20, 40), 0.05))
            elif cat == "ism":
                for _ in range(random.randint(1, 4)):
                    carriers.append((random.uniform(max(lo, lo_mhz), min(hi, hi_mhz)), random.uniform(12, 30), 0.2))
            elif cat in ("cellular", "pubsafety"):
                carriers.append(((max(lo, lo_mhz) + min(hi, hi_mhz)) / 2, random.uniform(15, 28), min(10.0, hi - lo)))
            elif cat == "satnav":
                carriers.append((c, random.uniform(8, 16), 2.0))

    for i in range(n):
        f_mhz = lo_mhz + i * step_hz / MHZ
        p = floor + random.uniform(-3, 3)
        for cm, strength, width in carriers:
            d = abs(f_mhz - cm)
            if d < width * 2:
                p = max(p, floor + strength * math.exp(-(d * d) / (2 * (width / 2.5) ** 2)))
        bins.append((f_mhz * MHZ, p))

    result = find_peaks(bins)
    return {"ok": True, "simulated": True,
            "sdr": {"available": False, "tool": "simulation"},
            "spectrum": _downsample(bins), "noise_floor_db": result["noise_floor_db"],
            "peaks": result["peaks"], "range": {"lo_mhz": lo_mhz, "hi_mhz": hi_mhz, "bin_khz": bin_khz}}


def simulate_preset(name: str) -> dict[str, Any]:
    p = PRESETS.get(name)
    if not p:
        return {"ok": False, "reason": "unknown_preset"}
    return simulate(p["lo"], p["hi"], p["bin_khz"])


# ===========================================================================
# BLE device identification  (works with the built-in Bluetooth radio)
# ===========================================================================

# Bluetooth SIG 16-bit company identifiers (common subset)
BLE_COMPANIES: dict[int, str] = {
    0x004C: "Apple", 0x0006: "Microsoft", 0x00E0: "Google", 0x0075: "Samsung",
    0x0171: "Amazon", 0x0087: "Garmin", 0x00D2: "Panasonic", 0x0157: "Huami (Amazfit)",
    0x0499: "Ruuvi", 0x05A7: "Sonos", 0x0059: "Nordic Semi", 0x0180: "Dexcom",
    0x03DA: "Logitech", 0x0201: "GN Netcom (Jabra)", 0x038F: "Xiaomi",
    0x0110: "Tile", 0x004F: "Fitbit", 0x02D0: "Google (Nest)", 0x00C4: "LG",
    0x0118: "TomTom", 0x008A: "Bose", 0x0A12: "Meta",
}

# Assigned service UUIDs (16-bit) that reveal a product/service
BLE_SERVICES_16: dict[str, str] = {
    "fe2c": "Google Fast Pair", "feed": "Tile tracker", "fd6f": "Exposure Notifications",
    "fe9f": "Google", "feaa": "Eddystone beacon", "fd5a": "Samsung SmartThings",
    "fe07": "Sonos", "fdcd": "Meta / Quest", "fd44": "Apple continuity",
    "180f": "Battery service", "180d": "Heart rate", "1812": "HID (keyboard/mouse)",
    "fe95": "Xiaomi MIoT", "fddf": "Harman", "fe61": "Logitech",
}

# Apple manufacturer-data first byte -> Continuity message type
APPLE_MSG: dict[int, str] = {
    0x02: "iBeacon", 0x05: "AirDrop", 0x07: "Proximity Pairing (AirPods)",
    0x08: "Hey Siri", 0x09: "AirPlay target", 0x0A: "AirPlay source",
    0x0C: "Handoff", 0x0D: "Tethering target", 0x0E: "Tethering source",
    0x0F: "Nearby Action", 0x10: "Nearby Info", 0x12: "Find My (offline finding)",
}


def _uuid16(u: str) -> str:
    """Normalize a full 128-bit assigned UUID to its 16-bit short form if it fits."""
    u = (u or "").lower().replace("-", "")
    if len(u) == 32 and u.endswith("00805f9b34fb") and u[4:8] == "0000":
        return u[0:4] if u[0:4] != "0000" else u[4:8]
    if len(u) == 32 and u[8:] == "00001000800000805f9b34fb":
        return u[4:8]
    return u[:4] if len(u) >= 4 else u


def classify_ble(manufacturer_data: dict | None, service_uuids: list | None,
                 name: str = "") -> dict[str, Any]:
    """Infer vendor / product / message-type from BLE advertisement contents.

    Everything here is drawn from the advertisement itself — public, passively
    broadcast fields. Randomized addresses still can't be tracked; this labels
    *what kind of thing* is advertising, not *who*.
    """
    out: dict[str, Any] = {"vendor": "", "product": "", "signals": []}

    # manufacturer data: {company_id_str: hexpayload}
    for cid_str, payload in (manufacturer_data or {}).items():
        try:
            cid = int(cid_str)
        except (ValueError, TypeError):
            continue
        vendor = BLE_COMPANIES.get(cid)
        if vendor:
            out["vendor"] = vendor
        if cid == 0x004C and payload:  # Apple Continuity
            try:
                first = int(payload[:2], 16)
                msg = APPLE_MSG.get(first)
                if msg:
                    out["signals"].append(f"Apple: {msg}")
                    if "Find My" in msg:
                        out["product"] = "Find My tag / lost device"
                    elif "AirPods" in msg:
                        out["product"] = "AirPods / pairing"
            except (ValueError, TypeError):
                pass
        elif cid == 0x0006 and payload:  # Microsoft Swift Pair / CDP
            out["signals"].append("Microsoft: CDP / Swift Pair")
        elif cid == 0x0110:
            out["product"] = "Tile tracker"

    # service UUIDs
    for u in (service_uuids or []):
        short = _uuid16(u)
        svc = BLE_SERVICES_16.get(short)
        if svc:
            out["signals"].append(svc)
            if not out["product"] and svc not in ("Battery service",):
                out["product"] = svc

    if name and not out["product"]:
        out["product"] = name

    out["summary"] = " · ".join(
        [x for x in [out["vendor"], out["product"]] if x] + out["signals"][:2]
    ) or "unclassified BLE"
    return out
