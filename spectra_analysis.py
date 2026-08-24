#!/usr/bin/env python3
"""
SPECTRA analysis engine — turns a raw surface into intelligence.

Everything here is deterministic and local. It runs on the report rows that
spectra.build_report() produces (the same shape the API serves), and it never
reaches the network. The optional AI layer in spectra_app.py consumes the
summary this module computes — so the model narrates real findings instead of
inventing them.

Core moves:
  * collapse virtual BSSIDs into inferred radios and physical devices
    (the "why am I seeing 38 networks" problem — usually a mesh),
  * map the SSID footprint (which names ride how many BSSIDs),
  * profile security posture and flag weak/open/hidden,
  * bucket channels into bands and find congestion,
  * read signal dynamics from the per-sweep RSSI series (fixed vs moving),
  * raise anomalies worth a human's attention.

Honesty constraints carried through, same as the rest of SPECTRA:
  * randomized addresses are transient — never folded into device identity,
  * range is a fuzzy log-distance estimate, not a coordinate,
  * bearing is unknown, so nothing here infers direction.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from typing import Any


# ---------------------------------------------------------------------------
# address helpers
# ---------------------------------------------------------------------------


def _real_label(label: str) -> str:
    """build_report emits '(hidden or unnamed)' for empty SSIDs; treat as blank."""
    if not label or label.strip().lower() in ("(hidden or unnamed)", "(hidden)"):
        return ""
    return label


def _octets(addr: str) -> list[str]:
    return addr.upper().split(":")


def oui(addr: str) -> str:
    return ":".join(_octets(addr)[:3])


def prefix40(addr: str) -> str:  # 40-bit prefix = a single radio's virtual BSSIDs
    return ":".join(_octets(addr)[:5])


# ---------------------------------------------------------------------------
# device clustering
# ---------------------------------------------------------------------------


def _single_linkage(items: list[dict], key: str, threshold: float) -> list[list[dict]]:
    """Group items whose `key` values chain together within `threshold`.

    Retained for callers that want plain chaining. Device clustering does NOT
    use this — see _link_radios for why.
    """
    ordered = sorted(items, key=lambda x: (x[key] is None, x.get(key) or 0))
    clusters: list[list[dict]] = []
    for it in ordered:
        v = it.get(key)
        placed = False
        if v is not None:
            for c in clusters:
                if any(m.get(key) is not None and abs(m[key] - v) <= threshold for m in c):
                    c.append(it)
                    placed = True
                    break
        if not placed:
            clusters.append([it])
    return clusters


def _ssid_compatible(a: dict, b: dict) -> bool:
    """Could these two radios be the same physical enclosure?

    If both broadcast named networks and share none, they are different boxes —
    two neighbours who both bought the same router, not one device. If either is
    hidden or unnamed we cannot rule the link out, so we allow it.
    """
    sa, sb = set(a.get("ssids") or []), set(b.get("ssids") or [])
    if not sa or not sb:
        return True
    return bool(sa & sb)


def _link_radios(items: list[dict], threshold: float) -> list[list[dict]]:
    """Cluster radios into enclosures using COMPLETE linkage plus an SSID gate.

    Complete linkage (every member within `threshold` of every other) rather
    than single linkage, because chaining is exactly the failure mode here: with
    single linkage a corridor of access points at -50/-55/-60/-65/-70 dBm all
    merge into one "device" spanning 20 dB, since each is within 6 dB of its
    neighbour. Complete linkage bounds the spread of any cluster at `threshold`.
    """
    ordered = sorted(items, key=lambda x: (x["rssi"] is None, x.get("rssi") or 0))
    clusters: list[list[dict]] = []
    for it in ordered:
        v = it.get("rssi")
        placed = False
        if v is not None:
            for c in clusters:
                if all(
                    m.get("rssi") is not None
                    and abs(m["rssi"] - v) <= threshold
                    and _ssid_compatible(m, it)
                    for m in c
                ):
                    c.append(it)
                    placed = True
                    break
        if not placed:
            clusters.append([it])
    return clusters


def cluster_devices(surface: list[dict]) -> dict[str, Any]:
    """Collapse BSSIDs -> radios -> inferred physical devices.

    Tier 1 (high confidence): BSSIDs sharing a 40-bit prefix are virtual APs on
    one radio. Amazon/eero-style meshes light up 6-18 of these per node.

    Tier 2 (medium confidence): within one OUI, radios whose signal sits within
    ~6 dB of EVERY other member of the cluster, and which do not broadcast
    mutually exclusive SSID sets, are likely the same physical enclosure (its
    2.4/5/6 GHz radios). Different rooms => different RSSI => different device,
    which is what separates the clusters.

    Two guards keep this honest. Linkage is complete, not single, so a cluster
    can never span more than the threshold — otherwise a corridor of same-vendor
    APs chains into one imaginary device. And two radios advertising different
    named networks are never merged, because that is two neighbours who bought
    the same router.

    Tier 2 is an ESTIMATE. bssid_count is measured and reliable; device_estimate
    is inference and is reported as medium confidence whenever it merges.

    Randomized emitters are excluded from device identity — they're transient
    and can't be attributed.
    """
    fixed = [r for r in surface if not r.get("randomized") and r.get("band") == "wifi"]

    # Tier 1: radios by 40-bit prefix
    radios_map: dict[str, list[dict]] = defaultdict(list)
    for r in fixed:
        radios_map[prefix40(r["addr"])].append(r)

    radios = []
    for pfx, members in radios_map.items():
        rssis = [m["rssi_median"] for m in members if m["rssi_median"] is not None]
        ssids = sorted({_real_label(m["label"]) for m in members if _real_label(m["label"])})
        radios.append(
            {
                "prefix": pfx,
                "oui": oui(members[0]["addr"]),
                "bssids": [m["addr"] for m in members],
                "bssid_count": len(members),
                "rssi": statistics.median(rssis) if rssis else None,
                "ssids": ssids,
                "hidden_count": sum(1 for m in members if not _real_label(m["label"])),
            }
        )

    # Tier 2: devices by OUI + RSSI proximity, requiring an SSID link when named
    by_oui: dict[str, list[dict]] = defaultdict(list)
    for rad in radios:
        by_oui[rad["oui"]].append(rad)

    devices = []
    for oui_key, rad_group in by_oui.items():
        for cluster in _link_radios(rad_group, threshold=6.0):
            all_ssids = sorted({s for rad in cluster for s in rad["ssids"]})
            all_bssids = [b for rad in cluster for b in rad["bssids"]]
            rssis = [rad["rssi"] for rad in cluster if rad["rssi"] is not None]
            devices.append(
                {
                    "oui": oui_key,
                    "vendor": next(
                        (r["vendor"] for r in fixed if oui(r["addr"]) == oui_key and r.get("vendor")),
                        "",
                    ),
                    "radio_count": len(cluster),
                    "bssid_count": len(all_bssids),
                    "bssids": all_bssids,
                    "ssids": all_ssids,
                    "rssi": statistics.median(rssis) if rssis else None,
                    "confidence": "high" if len(cluster) == 1 else "medium",
                }
            )

    devices.sort(key=lambda d: (d["rssi"] is None, -(d["rssi"] or -999)))
    bssid_total = len(fixed)
    return {
        "bssid_count": bssid_total,
        "radio_count": len(radios),
        "device_estimate": len(devices),
        "collapse_ratio": round(bssid_total / len(devices), 1) if devices else 1.0,
        "devices": devices,
    }


# ---------------------------------------------------------------------------
# SSID footprint
# ---------------------------------------------------------------------------


def ssid_footprint(surface: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    hidden = 0
    for r in surface:
        if r.get("band") != "wifi":
            continue
        lbl = _real_label(r["label"])
        if lbl:
            groups[lbl].append(r)
        else:
            hidden += 1
    out = []
    for ssid, members in groups.items():
        prefixes = {prefix40(m["addr"]) for m in members}
        out.append(
            {
                "ssid": ssid,
                "bssid_count": len(members),
                "radio_count": len(prefixes),
                "is_mesh": len(prefixes) > 1,
                "security": sorted({m["security"] for m in members if m["security"]}),
            }
        )
    out.sort(key=lambda x: -x["bssid_count"])
    return {"named": out, "hidden_bssids": hidden}


# ---------------------------------------------------------------------------
# security posture
# ---------------------------------------------------------------------------


def _sec_class(sec: str) -> str:
    s = (sec or "").upper()
    if not s or s in ("OPEN", "NONE"):
        return "open"
    if "WEP" in s:
        return "wep"
    if "WPA3" in s and "WPA2" in s:
        return "wpa2/3-transition"
    if "WPA3" in s:
        return "wpa3"
    if "WPA2" in s:
        return "wpa2"
    if "WPA" in s:
        return "wpa"
    return "other"


def security_posture(surface: list[dict]) -> dict[str, Any]:
    counts: dict[str, int] = defaultdict(int)
    weak = []
    for r in surface:
        if r.get("band") != "wifi":
            continue
        cls = _sec_class(r["security"])
        counts[cls] += 1
        if cls in ("open", "wep", "wpa"):
            weak.append({"addr": r["addr"], "label": _real_label(r["label"]) or "(hidden)", "class": cls, "rssi": r["rssi_median"]})
    weak.sort(key=lambda x: (x["rssi"] is None, -(x["rssi"] or -999)))
    return {"counts": dict(counts), "weak": weak}


# ---------------------------------------------------------------------------
# channel / band analysis
# ---------------------------------------------------------------------------


def _band(chan: str) -> str:
    try:
        c = int(str(chan).strip())
    except (ValueError, AttributeError):
        return "unknown"
    if 1 <= c <= 14:
        return "2.4 GHz"
    if 32 <= c <= 177:
        return "5 GHz"
    if c >= 181:
        return "6 GHz"
    return "unknown"


def channel_analysis(surface: list[dict]) -> dict[str, Any]:
    band_counts: dict[str, int] = defaultdict(int)
    chan_counts: dict[str, int] = defaultdict(int)
    for r in surface:
        if r.get("band") != "wifi" or not r.get("channel"):
            continue
        band_counts[_band(r["channel"])] += 1
        chan_counts[str(r["channel"])] += 1
    # 2.4 GHz congestion: how loaded are 1/6/11
    twofour = {c: n for c, n in chan_counts.items() if _band(c) == "2.4 GHz"}
    busiest = sorted(twofour.items(), key=lambda kv: -kv[1])[:3]
    return {
        "bands": dict(band_counts),
        "channels": dict(sorted(chan_counts.items(), key=lambda kv: -kv[1])),
        "busiest_24ghz": busiest,
    }


# ---------------------------------------------------------------------------
# signal dynamics (from per-sweep RSSI series)
# ---------------------------------------------------------------------------


# Movement is judged over the most recent sweeps only. Across a whole session
# the span of a perfectly stationary access point grows without bound — normal
# multipath jitter of a few dB will eventually touch every value in a 10 dB
# range, and then everything in the room reads as "moving".
DYNAMICS_WINDOW = 12


def signal_dynamics(surface: list[dict], window: int = DYNAMICS_WINDOW) -> dict[str, Any]:
    moving = []
    for r in surface:
        full = r.get("rssi_series") or []
        series = full[-window:] if window and window > 0 else full
        if len(series) < 3:
            continue
        span = max(series) - min(series)
        trend = series[-1] - series[0]
        if span >= 10 or abs(trend) >= 8:
            moving.append(
                {
                    "addr": r["addr"],
                    "label": _real_label(r["label"]) or "(hidden)",
                    "span_db": span,
                    "trend_db": trend,
                    "samples": len(series),
                    "randomized": bool(r.get("randomized")),
                    "direction": "approaching" if trend > 0 else "receding" if trend < 0 else "flat",
                }
            )
    moving.sort(key=lambda x: -x["span_db"])
    return {"variable": moving, "variable_count": len(moving)}


# ---------------------------------------------------------------------------
# anomalies
# ---------------------------------------------------------------------------


def anomalies(surface: list[dict], devices: dict[str, Any]) -> list[dict]:
    out: list[dict] = []

    opens = [r for r in surface if r.get("band") == "wifi" and _sec_class(r["security"]) == "open"]
    if opens:
        out.append({"level": "warn", "kind": "open_network", "count": len(opens),
                    "detail": f"{len(opens)} open (unencrypted) Wi-Fi BSSID(s) in range."})

    wep = [r for r in surface if _sec_class(r["security"]) == "wep"]
    if wep:
        out.append({"level": "high", "kind": "wep", "count": len(wep),
                    "detail": f"{len(wep)} BSSID(s) using WEP — broken encryption."})

    rnd = [r for r in surface if r.get("randomized")]
    if rnd:
        out.append({"level": "info", "kind": "randomized", "count": len(rnd),
                    "detail": f"{len(rnd)} emitter(s) with randomized addresses — transient, not attributable."})

    unknown_oui = [r for r in surface if r.get("band") == "wifi" and not r.get("randomized")
                   and (not r.get("vendor") or r["vendor"] in ("", "—"))]
    if unknown_oui:
        out.append({"level": "info", "kind": "unknown_vendor", "count": len(unknown_oui),
                    "detail": f"{len(unknown_oui)} BSSID(s) with an unrecognized OUI — run `spectra.py refresh-oui` to resolve vendors from the IEEE registry."})

    # oversized mesh: a single device fanning many BSSIDs, or one SSID spread
    # across several nodes (classic mesh footprint)
    for d in devices.get("devices", []):
        if d["bssid_count"] >= 4:
            name = d["ssids"][0] if d["ssids"] else d["oui"]
            out.append({"level": "info", "kind": "mesh", "count": d["bssid_count"],
                        "detail": f"'{name}' is one device presenting {d['bssid_count']} BSSIDs across {d['radio_count']} radio(s) — mesh/multi-band, not separate networks."})

    # SSID carried by multiple physical nodes = a mesh deployment
    ssid_nodes: dict[str, int] = defaultdict(int)
    for d in devices.get("devices", []):
        for s in d["ssids"]:
            ssid_nodes[s] += 1
    for ssid, nodes in ssid_nodes.items():
        if nodes >= 2:
            out.append({"level": "info", "kind": "mesh_ssid", "count": nodes,
                        "detail": f"'{ssid}' is served by {nodes} physical nodes — a mesh network, likely one household/office."})

    # something physically very close
    immediate = [r for r in surface if r.get("range_m") is not None and r["range_m"] < 2
                 and not r.get("randomized")]
    if immediate:
        strongest = min(immediate, key=lambda r: r["range_m"])
        out.append({"level": "info", "kind": "immediate", "count": len(immediate),
                    "detail": f"{len(immediate)} emitter(s) inside ~2m — closest is {strongest['label'] or strongest['addr']} at ~{strongest['range_m']}m."})

    order = {"high": 0, "warn": 1, "info": 2}
    out.sort(key=lambda a: order.get(a["level"], 3))
    return out


# ---------------------------------------------------------------------------
# top-level summary (feeds both the UI panel and the AI layer)
# ---------------------------------------------------------------------------


def analyze(surface: list[dict]) -> dict[str, Any]:
    devices = cluster_devices(surface)
    return {
        "totals": {
            "emitters": len(surface),
            "wifi": sum(1 for r in surface if r.get("band") == "wifi"),
            "ble": sum(1 for r in surface if r.get("band") == "ble"),
            "randomized": sum(1 for r in surface if r.get("randomized")),
        },
        "devices": devices,
        "ssids": ssid_footprint(surface),
        "security": security_posture(surface),
        "channels": channel_analysis(surface),
        "dynamics": signal_dynamics(surface),
        "anomalies": anomalies(surface, devices),
    }


def ai_brief(summary: dict[str, Any]) -> dict[str, Any]:
    """A compact, token-lean projection of the analysis for the model.

    Deliberately drops full BSSID lists and keeps counts, top devices, security
    mix, congestion, and anomalies — enough to reason over, cheap to send.
    """
    dev = summary["devices"]
    top_devices = [
        {
            "vendor": d["vendor"] or "unknown",
            "ssids": d["ssids"][:3],
            "bssids": d["bssid_count"],
            "radios": d["radio_count"],
            "rssi": d["rssi"],
            "confidence": d["confidence"],
        }
        for d in dev["devices"][:8]
    ]
    return {
        "totals": summary["totals"],
        "device_estimate": dev["device_estimate"],
        "bssid_count": dev["bssid_count"],
        "collapse_ratio": dev["collapse_ratio"],
        "top_devices": top_devices,
        "security_counts": summary["security"]["counts"],
        "weak_security": summary["security"]["weak"][:5],
        "bands": summary["channels"]["bands"],
        "busiest_24ghz": summary["channels"]["busiest_24ghz"],
        "variable_signals": summary["dynamics"]["variable"][:5],
        "hidden_bssids": summary["ssids"]["hidden_bssids"],
        "anomalies": summary["anomalies"],
    }
