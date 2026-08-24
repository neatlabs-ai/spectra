#!/usr/bin/env python3
"""
SPECTRA server — live passive RF surface console over HTTP.

Wraps the collection engine in spectra.py with:
  * a background sweep loop you can start/stop from the UI,
  * Server-Sent Events so the browser updates the instant a sweep lands,
  * a small REST surface (report, one-shot sweep, k-anonymity demo),
  * the console UI served from the same origin (no build step, no CORS).

Run:
    pip install flask
    python spectra_app.py                 # live: uses your real radios
    python spectra_app.py --demo          # seed a synthetic field (no radios)
    python spectra_app.py --host 0.0.0.0 --port 8700

Then open http://127.0.0.1:8700

The scanning is receive-only and inherits every constraint from spectra.py:
no monitor mode, no injection, no association. Randomized addresses are
flagged, not tracked. Range is a log-distance estimate with error bars, and
bearing is never shown because a passive single antenna can't measure it.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import random
import threading
import time
from datetime import datetime, timezone, timedelta

try:
    import spectra
except ImportError:
    raise SystemExit(
        "spectra.py must sit next to spectra_app.py — it's the collection engine.\n"
        "Keep both files in the same folder and run again."
    )

try:
    import spectra_analysis as analysis
except ImportError:
    raise SystemExit("spectra_analysis.py must sit next to spectra_app.py — it's the analysis engine.")

try:
    import spectra_rf as rf
except ImportError:
    raise SystemExit("spectra_rf.py must sit next to spectra_app.py — it's the RF/SDR engine.")

try:
    import spectra_watch as watch
except ImportError:
    raise SystemExit("spectra_watch.py must sit next to spectra_app.py — it's the watchlist engine.")

from pathlib import Path

watchlist = watch.Watchlist()


class Settings:
    """User settings incl. API keys. In-memory by default; opt-in disk persist.

    This is a local single-user tool. Keys live in server memory for the
    session. If the user checks 'save to disk', they're written to
    ~/.spectra/config.json with 0600 perms. Nothing is sent anywhere except the
    API the key belongs to.
    """

    KNOWN = {"anthropic_api_key"}

    def __init__(self):
        self._store: dict[str, str] = {}
        self._path = Path.home() / ".spectra" / "config.json"
        self._persisted = False
        self._load()

    def _load(self):
        if self._path.exists():
            try:
                self._store = json.loads(self._path.read_text())
                self._persisted = True
            except Exception:
                self._store = {}

    def get(self, key: str) -> str | None:
        return self._store.get(key)

    def set_keys(self, updates: dict, persist: bool = False) -> None:
        for k, v in updates.items():
            if k in self.KNOWN and isinstance(v, str) and v.strip():
                self._store[k] = v.strip()
        if persist:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(json.dumps(self._store))
            try:
                self._path.chmod(0o600)
            except OSError:
                pass
            self._persisted = True

    def clear(self, key: str) -> None:
        self._store.pop(key, None)
        if self._persisted and self._path.exists():
            self._path.write_text(json.dumps(self._store))

    @staticmethod
    def _mask(v: str) -> str:
        if not v:
            return ""
        return f"{v[:6]}…{v[-4:]}" if len(v) > 12 else "set"

    def masked(self) -> dict:
        return {
            "anthropic_api_key": self._mask(self._store.get("anthropic_api_key", "")),
            "has_anthropic": bool(self._store.get("anthropic_api_key")),
            "persisted": self._persisted,
        }


settings = Settings()

try:
    from flask import Flask, Response, request, jsonify
except ImportError:
    raise SystemExit("This app needs Flask:  pip install flask")


# ---------------------------------------------------------------------------
# collector: background sweep loop + pub/sub to SSE subscribers
# ---------------------------------------------------------------------------


class Collector:
    def __init__(self, interval: int = 20, ble_seconds: float = 6.0):
        self.interval = interval
        self.ble_seconds = ble_seconds
        self.want_wifi = True
        self.want_ble = True

        self._subs: list[queue.Queue] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None
        self._oui = spectra.load_oui()

        self.sweep_count = 0
        self.last_sweep: str | None = None
        self.last_error: str | None = None

    # -- pub/sub ------------------------------------------------------------

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=16)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    # How far back a surface report reaches. See spectra.DEFAULT_WINDOW_HOURS.
    window_hours: float | None = None

    # Delete observations older than this after each sweep. None/0 = keep all.
    retain_hours: float | None = None

    def _publish(self, event: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass  # slow client; drop rather than block the sweep loop

    # -- collection ---------------------------------------------------------

    def current_surface(self, window_hours: float | None = None) -> list[dict]:
        conn = spectra.db()
        try:
            w = self.window_hours if window_hours is None else window_hours
            return watch.annotate(spectra.build_report(conn, window_hours=w), watchlist)
        finally:
            conn.close()

    def sweep_once(self) -> tuple[int, list[dict]]:
        conn = spectra.db()
        try:
            batch = []
            if self.want_wifi:
                batch.extend(spectra.scan_wifi())
            if self.want_ble:
                batch.extend(spectra.scan_ble(self.ble_seconds))
            for o in batch:
                o.vendor = spectra.vendor_for(o.addr, self._oui)
                o.randomized = spectra.is_randomized(o.addr)
            n = spectra.persist(conn, batch)
            if self.retain_hours:
                spectra.prune(conn, self.retain_hours)
            surface = watch.annotate(
                spectra.build_report(conn, window_hours=self.window_hours), watchlist
            )
        finally:
            conn.close()

        self.sweep_count += 1
        self.last_sweep = spectra.now_iso()
        self.last_error = None
        self._publish(
            {
                "type": "sweep",
                "observations": n,
                "sweep": self.sweep_count,
                "ts": self.last_sweep,
                "running": self._running,
                "surface": surface,
            }
        )
        return n, surface

    def _loop(self) -> None:
        while self._running:
            try:
                self.sweep_once()
            except Exception as exc:  # keep the loop alive on transient radio errors
                self.last_error = str(exc)
                self._publish({"type": "error", "message": str(exc)})
            # interruptible sleep
            for _ in range(max(1, self.interval)):
                if not self._running:
                    break
                time.sleep(1)

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self._publish({"type": "state", "running": True})

    def stop(self) -> None:
        self._running = False
        self._publish({"type": "state", "running": False})

    @property
    def running(self) -> bool:
        return self._running

    def state(self) -> dict:
        return {
            "running": self._running,
            "interval": self.interval,
            "ble_seconds": self.ble_seconds,
            "want_wifi": self.want_wifi,
            "want_ble": self.want_ble,
            "sweep_count": self.sweep_count,
            "last_sweep": self.last_sweep,
            "last_error": self.last_error,
        }


collector = Collector()


# ---------------------------------------------------------------------------
# demo seeding — lets the app be shown on a box with no radios
# ---------------------------------------------------------------------------


def seed_demo() -> int:
    specs = [
        ("wifi", "B8:27:EB:11:22:33", "HOMENET", "WPA2-Personal", "36", -49),
        ("wifi", "24:5A:4C:01:02:03", "Guest WiFi", "WPA2 WPA3", "11", -68),
        ("wifi", "D8:5D:4C:9A:2B:70", "TP-LINK_2G", "WPA2-Personal", "6", -74),
        ("wifi", "DA:A1:19:AA:BB:CC", "", "Open", "1", -86),
        ("ble", "F4:F5:D8:44:55:66", "Nest Cam", "", "", -61),
        ("ble", "EC:B5:FA:12:34:56", "Hue lamp", "", "", -55),
        ("ble", "4C:87:5D:E1:9F:02", "", "", "", -70),
        ("ble", "C8:D0:83:77:1A:E4", "Echo Dot", "", "", -78),
    ]
    oui = spectra.load_oui()
    conn = spectra.db()
    base = datetime.now(timezone.utc) - timedelta(minutes=5)
    total = 0
    try:
        # Reset first: without this, every --demo launch stacks another six
        # sweeps onto the last run's data and the RSSI series grows forever.
        conn.execute("DELETE FROM observations")
        conn.commit()
        for sweep in range(6):
            batch = []
            ts = (base + timedelta(seconds=sweep * 50)).isoformat(timespec="seconds")
            for band, addr, label, sec, ch, rssi in specs:
                o = spectra.Observation(
                    ts=ts,
                    band=band,
                    addr=addr,
                    label=label,
                    rssi=rssi + random.randint(-4, 4),
                    channel=ch,
                    security=sec,
                )
                o.vendor = spectra.vendor_for(addr, oui)
                o.randomized = spectra.is_randomized(addr)
                batch.append(o)
            total += spectra.persist(conn, batch)
    finally:
        conn.close()
    return total


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# --- request guard ---------------------------------------------------------
# The console has no login, which is fine while it is bound to loopback — but
# "bound to loopback" does not mean "unreachable from the web". Any page you
# visit can make your browser POST to 127.0.0.1, and any hostname that resolves
# to 127.0.0.1 can be used to reach it with a foreign Origin (DNS rebinding).
#
# Two cheap gates close both:
#   1. Host must be a loopback name. Blocks rebinding.
#   2. State-changing requests must not come from a foreign origin. Blocks the
#      cross-site form POST that could silently clear a watchlist or spend the
#      API key on /api/ai.
#
# This is not authentication. It stops a drive-by; it does not make the console
# safe to expose. Keep it on 127.0.0.1.
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "[::1]", "::1"}


def _host_ok(host: str) -> bool:
    if not host:
        return False
    name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    return name.strip("[]") in {h.strip("[]") for h in ALLOWED_HOSTS}


@app.before_request
def _guard():
    if not _host_ok(request.host):
        return jsonify({
            "ok": False,
            "error": "host_not_allowed",
            "detail": (
                f"Refusing request for host {request.host!r}. SPECTRA only answers "
                "on 127.0.0.1 / localhost. If you meant to expose it, put real "
                "authentication in front of it first."
            ),
        }), 403

    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None

    # Sec-Fetch-Site is sent by every current browser and cannot be forged by
    # page script. Absent (curl, older clients) we fall back to Origin/Referer.
    site = request.headers.get("Sec-Fetch-Site")
    if site and site not in ("same-origin", "none"):
        return jsonify({"ok": False, "error": "cross_site_blocked",
                        "detail": "Cross-site state change refused."}), 403

    origin = request.headers.get("Origin") or request.headers.get("Referer")
    if origin:
        from urllib.parse import urlparse
        h = urlparse(origin).netloc
        if not _host_ok(h):
            return jsonify({"ok": False, "error": "cross_origin_blocked",
                            "detail": f"Refusing state change from origin {origin!r}."}), 403
    return None


def _sse(event: dict) -> str:
    return f"data: {json.dumps(event)}\n\n"


@app.route("/")
def index() -> Response:
    return Response(CONSOLE_HTML, mimetype="text/html")


@app.route("/api/state")
def api_state():
    return jsonify(collector.state())


@app.route("/api/surface")
def api_surface():
    return jsonify({"surface": collector.current_surface(), "state": collector.state()})


@app.route("/api/sweep", methods=["POST"])
def api_sweep():
    n, surface = collector.sweep_once()
    return jsonify({"observations": n, "surface": surface, "state": collector.state()})


@app.route("/api/control", methods=["POST"])
def api_control():
    body = request.get_json(silent=True) or {}
    action = body.get("action")
    if "interval" in body:
        try:
            collector.interval = max(3, int(body["interval"]))
        except (TypeError, ValueError):
            pass
    if "want_wifi" in body:
        collector.want_wifi = bool(body["want_wifi"])
    if "want_ble" in body:
        collector.want_ble = bool(body["want_ble"])
    if action == "start":
        collector.start()
    elif action == "stop":
        collector.stop()
    return jsonify(collector.state())


@app.route("/api/kanon", methods=["POST"])
def api_kanon():
    body = request.get_json(silent=True) or {}
    secret = body.get("secret", "")
    if not secret:
        return jsonify({"error": "provide a secret to check"}), 400
    try:
        return jsonify(spectra.kanon_lookup(secret))
    except Exception as exc:  # never leak a 500 page into the UI's JSON parse
        return jsonify({"error": f"lookup failed: {exc.__class__.__name__}"})


@app.route("/api/analysis")
def api_analysis():
    return jsonify(analysis.analyze(collector.current_surface()))


# --- optional AI layer -----------------------------------------------------

AI_MODEL = os.environ.get("SPECTRA_AI_MODEL", "claude-sonnet-5")
AI_SYSTEM = (
    "You are a wireless-security analyst reading a passive RF survey the operator "
    "collected in their own environment. You are given a computed summary — device "
    "clustering, security mix, channel congestion, signal dynamics, anomalies — not raw "
    "packets. Write a tight, practitioner-level read: what's notable, what's probably one "
    "physical device vs many, any security concerns, and what's worth checking next. "
    "Prioritize; don't just restate the numbers. Hard rules you must respect: randomized "
    "MAC addresses are transient and cannot be attributed to a person or tracked across "
    "sessions; range is a rough log-distance estimate, never a coordinate; bearing/direction "
    "is unknown. Don't speculate about identities beyond what the OUI and patterns support. "
    "Be concrete and brief — a few short paragraphs, no preamble."
)


def _anthropic_key() -> str | None:
    return (
        settings.get("anthropic_api_key")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("SPECTRA_ANTHROPIC_KEY")
    )


@app.route("/api/ai/status")
def api_ai_status():
    return jsonify({"enabled": bool(_anthropic_key()), "model": AI_MODEL})


@app.route("/api/ai", methods=["POST"])
def api_ai():
    key = _anthropic_key()
    if not key:
        return jsonify({"error": "AI is off — set ANTHROPIC_API_KEY in the environment and restart to enable."}), 200

    try:
        import requests
    except ImportError:
        return jsonify({"error": "requests not installed (pip install requests)"}), 200

    summary = analysis.analyze(collector.current_surface())
    brief = analysis.ai_brief(summary)

    body = {
        "model": AI_MODEL,
        "max_tokens": 1024,
        "system": AI_SYSTEM,
        "messages": [
            {
                "role": "user",
                "content": "Here is the computed surface summary as JSON. Give me your read.\n\n"
                + json.dumps(brief, indent=2),
            }
        ],
    }
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=body,
            timeout=60,
        )
        if resp.status_code != 200:
            return jsonify({"error": f"model API returned {resp.status_code}", "detail": resp.text[:300]}), 200
        data = resp.json()
        text = "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        ).strip()
        return jsonify({"analysis": text or "(empty response)", "model": AI_MODEL, "brief": brief})
    except requests.RequestException as exc:
        return jsonify({"error": f"couldn't reach the model API ({exc.__class__.__name__})"}), 200


@app.route("/api/settings", methods=["GET"])
def api_settings_get():
    return jsonify({"keys": settings.masked(), "ai_model": AI_MODEL})


@app.route("/api/settings", methods=["POST"])
def api_settings_post():
    body = request.get_json(silent=True) or {}
    persist = bool(body.get("persist"))
    updates = {}
    if "anthropic_api_key" in body:
        updates["anthropic_api_key"] = body["anthropic_api_key"]
    if body.get("clear_anthropic"):
        settings.clear("anthropic_api_key")
    if updates:
        settings.set_keys(updates, persist=persist)
    return jsonify({"keys": settings.masked(), "ai_enabled": bool(_anthropic_key())})


# --- RF / SDR spectrum ------------------------------------------------------


@app.route("/api/rf/status")
def api_rf_status():
    return jsonify({"sdr": rf.detect_sdr(), "presets": {
        k: {"lo_mhz": v["lo"], "hi_mhz": v["hi"], "title": v["title"]}
        for k, v in rf.PRESETS.items()
    }})


@app.route("/api/rf/scan", methods=["POST"])
def api_rf_scan():
    body = request.get_json(silent=True) or {}
    preset = body.get("preset")
    sim = bool(body.get("simulate"))
    sdr = rf.detect_sdr()

    # auto-fall back to simulation when no hardware, unless a real scan is forced
    if not sdr["available"] and not body.get("force_live"):
        sim = True

    try:
        if preset:
            result = rf.simulate_preset(preset) if sim else rf.scan_preset(preset)
        else:
            lo = float(body.get("lo_mhz", 88))
            hi = float(body.get("hi_mhz", 108))
            bink = float(body.get("bin_khz", 100))
            result = rf.simulate(lo, hi, bink) if sim else rf.scan(lo, hi, bink)
    except Exception as exc:
        return jsonify({"ok": False, "reason": f"{exc.__class__.__name__}: {exc}"}), 200

    return jsonify(result)


# --- watchlist + modes ------------------------------------------------------


@app.route("/api/watchlist", methods=["GET"])
def api_watchlist_get():
    return jsonify(watchlist.as_dict())


@app.route("/api/watchlist/add", methods=["POST"])
def api_watchlist_add():
    body = request.get_json(silent=True) or {}
    which = body.get("list", "allow")
    if which not in ("allow", "block"):
        return jsonify({"error": "list must be allow or block"}), 400
    ok = watchlist.add(body.get("mac", ""), which, body.get("label", ""))
    if not ok:
        return jsonify({"error": "invalid MAC"}), 400
    return jsonify(watchlist.as_dict())


@app.route("/api/watchlist/import", methods=["POST"])
def api_watchlist_import():
    body = request.get_json(silent=True) or {}
    which = body.get("list", "allow")
    if which not in ("allow", "block"):
        return jsonify({"error": "list must be allow or block"}), 400
    n = watchlist.import_text(body.get("text", ""), which)
    return jsonify({"imported": n, **watchlist.as_dict()})


@app.route("/api/watchlist/remove", methods=["POST"])
def api_watchlist_remove():
    body = request.get_json(silent=True) or {}
    which = body.get("list", "allow")
    watchlist.remove(body.get("mac", ""), which)
    return jsonify(watchlist.as_dict())


@app.route("/api/watchlist/clear", methods=["POST"])
def api_watchlist_clear():
    body = request.get_json(silent=True) or {}
    which = body.get("list", "allow")
    if which in ("allow", "block"):
        watchlist.clear(which)
    return jsonify(watchlist.as_dict())


@app.route("/api/finder")
def api_finder():
    surface = collector.current_surface()
    fp = request.args.get("fingerprint", "1") != "0"
    return jsonify({"matches": watch.finder_view(surface, include_fingerprint=fp),
                    "allow_count": watchlist.as_dict()["allow_count"]})


@app.route("/api/sweep_scan")
def api_sweep_scan():
    surface = collector.current_surface()
    return jsonify({"flags": watch.sweep_view(surface),
                    "block_count": watchlist.as_dict()["block_count"]})


@app.route("/api/stream")
def api_stream():
    def gen():
        q = collector.subscribe()
        # immediate snapshot so a fresh page paints without waiting for a sweep
        yield _sse(
            {
                "type": "snapshot",
                "surface": collector.current_surface(),
                "running": collector.running,
                "sweep": collector.sweep_count,
                "state": collector.state(),
            }
        )
        try:
            while True:
                try:
                    yield _sse(q.get(timeout=15))
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            collector.unsubscribe(q)

    return Response(
        gen(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


# ---------------------------------------------------------------------------
# UI  (vanilla JS port of the console — same design language, same math)
# ---------------------------------------------------------------------------

CONSOLE_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SPECTRA — Passive RF Surface</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --ink:#0A0D18; --ink2:#0E1224; --panel:#12172B; --panel2:#171D36;
  --line:#232B4A; --line2:#2E3860; --txt:#E7EBF7; --hi:#F2F5FF;
  --mid:#8A93B4; --muted:#646E92; --hot:#FF7A45; --amber:#F2B33D; --good:#4FD6A0;
}
*{box-sizing:border-box}
html,body{margin:0}
body{background:var(--ink);color:var(--txt);font-family:'Chakra Petch',sans-serif;-webkit-font-smoothing:antialiased}
.mono{font-family:'JetBrains Mono',monospace}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:var(--ink2)}
::-webkit-scrollbar-thumb{background:var(--line2);border-radius:4px}
button{font-family:inherit}
button:focus-visible{outline:2px solid var(--amber);outline-offset:2px}
a{color:var(--amber)}
header{border-bottom:1px solid var(--line);background:linear-gradient(180deg,var(--ink2),var(--ink))}
.wrap{max-width:1240px;margin:0 auto;padding:16px 22px}
.brandrow{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px}
.brand{display:flex;align-items:center;gap:12px}
.glyph{width:34px;height:34px;border-radius:9px;background:linear-gradient(135deg,var(--hot),var(--amber));display:flex;align-items:center;justify-content:center;color:var(--ink);font-weight:700}
.title{font-weight:700;font-size:19px;letter-spacing:4px;color:var(--hi)}
.subtitle{font-size:10px;letter-spacing:3px;color:var(--muted);margin-top:-2px}
.ctrls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.btn{display:flex;align-items:center;gap:8px;padding:9px 14px;border-radius:9px;background:var(--panel);border:1px solid var(--line2);color:var(--txt);cursor:pointer;font-size:12.5px;letter-spacing:1px}
.btn.mono{font-family:'JetBrains Mono',monospace}
.btn:hover{border-color:var(--amber)}
.btn.primary{background:linear-gradient(135deg,var(--hot),var(--amber));border:none;color:var(--ink);font-weight:600}
.btn.stop{background:rgba(255,122,69,.12);border-color:rgba(255,122,69,.4);color:var(--hot)}
.statbar{display:flex;align-items:center;padding:0 22px 16px;max-width:1240px;margin:0 auto;flex-wrap:wrap;gap:12px 0}
.stat{padding:0 18px;border-left:1px solid var(--line)}
.stat:first-child{border-left:none;padding-left:0}
.stat .l{font-size:10px;letter-spacing:2px;color:var(--muted)}
.stat .v{font-size:22px;font-weight:600;color:var(--hi);line-height:1.2;margin-top:2px}
.live{display:inline-flex;align-items:center;gap:7px;font-size:11px;letter-spacing:2px;color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.dot.on{background:var(--good);box-shadow:0 0 0 0 rgba(79,214,160,.6);animation:pulse 1.8s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(79,214,160,.5)}70%{box-shadow:0 0 0 7px rgba(79,214,160,0)}100%{box-shadow:0 0 0 0 rgba(79,214,160,0)}}
main{max-width:1240px;margin:0 auto;padding:22px}
.grid{display:grid;grid-template-columns:1fr 380px;gap:22px;align-items:start}
.card{background:var(--panel);border:1px solid var(--line);border-radius:14px}
.card.pad{padding:10px 10px 14px}
.fieldhead{display:flex;justify-content:space-between;align-items:center;padding:6px 10px 10px}
.fieldhead .l{font-size:11px;letter-spacing:2px;color:var(--mid)}
.fieldhead .r{font-size:10px;letter-spacing:1px;color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:10px 20px;padding:8px 12px 2px;align-items:center}
.leg{display:flex;align-items:center;gap:7px;font-size:11px;color:var(--mid)}
.chips{display:flex;gap:8px;padding:14px 14px 12px;flex-wrap:wrap}
.chip{padding:6px 12px;border-radius:8px;cursor:pointer;background:transparent;border:1px solid var(--line);color:var(--mid);font-size:12px;letter-spacing:1px;display:flex;align-items:center;gap:6px}
.chip.active{background:var(--panel2);border-color:var(--line2);color:var(--hi)}
.chip .c{color:var(--muted);font-size:11px}
.ledhead{display:flex;padding:0 14px 8px;border-bottom:1px solid var(--line)}
.ledhead button{background:none;border:none;cursor:pointer;text-align:left;padding:0;font-size:10px;letter-spacing:2px;color:var(--muted);display:flex;gap:4px;align-items:center}
.ledhead button.act{color:var(--amber)}
.ledbody{max-height:300px;overflow-y:auto}
.row{display:flex;align-items:center;width:100%;padding:11px 14px;background:transparent;border:none;border-left:2px solid transparent;border-bottom:1px solid var(--line);cursor:pointer;text-align:left}
.row.sel{background:var(--panel2)}
.row:hover{background:var(--ink2)}
.detail{min-height:420px;position:sticky;top:22px;overflow:hidden}
.d-pad{padding:18px 20px 28px;overflow-y:auto}
.frow{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--line);gap:16px}
.frow .k{font-size:10.5px;letter-spacing:2px;color:var(--muted);text-transform:uppercase;flex-shrink:0}
.frow .val{font-size:13.5px;color:var(--txt);text-align:right}
.warn{margin-top:16px;padding:12px 14px;background:rgba(255,122,69,.08);border:1px solid rgba(255,122,69,.35);border-radius:10px;display:flex;gap:10px;font-size:12.5px;color:#FFD3BF;line-height:1.5}
.empty{padding:40px 26px;text-align:center;color:var(--mid)}
.kbox{margin:16px 14px;padding:14px;background:var(--ink2);border:1px solid var(--line);border-radius:10px}
.kbox input{width:100%;background:var(--panel);border:1px solid var(--line2);border-radius:8px;color:var(--txt);padding:9px 10px;font-family:'JetBrains Mono',monospace;font-size:12.5px;margin:8px 0}
.kres{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--mid);line-height:1.6;white-space:pre-wrap}
footer{margin-top:26px;padding-top:16px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted);font-family:'JetBrains Mono',monospace;line-height:1.7}
.toast{max-width:1240px;margin:12px auto 0;padding:0 22px}
.toast .in{padding:10px 14px;border-radius:9px;font-size:12.5px;font-family:'JetBrains Mono',monospace}
.toast .ok{background:rgba(79,214,160,.08);border:1px solid rgba(79,214,160,.35);color:#8FEFC6}
.toast .err{background:rgba(255,122,69,.08);border:1px solid rgba(255,122,69,.35);color:#FFD3BF}
@media (max-width:900px){.grid{grid-template-columns:1fr}.detail{position:static}}
@media (prefers-reduced-motion:reduce){.dot.on{animation:none}.ping{display:none}}
.modebtn{background:transparent;border:none;padding:9px 16px;cursor:pointer;font-size:12px;letter-spacing:1.5px;color:var(--mid);border-right:1px solid var(--line2)}
.modebtn:last-child{border-right:none}
.modebtn.active{background:var(--panel2);color:var(--hi)}
.wltab,.helptab{background:transparent;border:none;padding:9px 16px;cursor:pointer;font-size:11.5px;letter-spacing:1px;color:var(--mid);border-right:1px solid var(--line2)}
.helptab{border-right:none;border-bottom:2px solid transparent;white-space:nowrap}
.wltab.active{background:var(--panel2);color:var(--hi)}
.helptab.active{color:var(--amber);border-bottom-color:var(--amber)}
.bigrssi{font-family:'Chakra Petch',sans-serif;font-weight:700;font-size:42px;line-height:1}
.warm{color:#4FD6A0}.cold{color:#7CC7E8}.flatt{color:var(--muted)}
.hgrid{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;margin:14px 0}
.hgrid .n{width:22px;height:22px;border-radius:50%;background:var(--amber);color:var(--ink);font-family:'JetBrains Mono';font-size:12px;font-weight:600;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.helpBody h3{font-family:'Chakra Petch';font-size:15px;color:var(--hi);margin:18px 0 8px;letter-spacing:1px}
.helpBody code{font-family:'JetBrains Mono';font-size:12px;background:var(--ink2);border:1px solid var(--line);border-radius:4px;padding:1px 6px;color:var(--amber)}
.helpBody p{margin:8px 0}
.helpBody .note{background:var(--ink2);border:1px solid var(--line);border-left:2px solid var(--amber);border-radius:8px;padding:12px 14px;margin:12px 0;font-size:12.5px;color:var(--mid)}
</style>
</head>
<body>
<header>
  <div class="wrap brandrow">
    <div class="brand">
      <div class="glyph">✛</div>
      <div>
        <div class="title">SPECTRA</div>
        <div class="subtitle mono">PASSIVE RF SURFACE</div>
      </div>
    </div>
    <div class="ctrls">
      <span class="live"><span id="livedot" class="dot"></span><span id="livetext" class="mono">IDLE</span></span>
      <button id="sweepBtn" class="btn mono">SWEEP ONCE</button>
      <button id="liveBtn" class="btn primary mono">START LIVE</button>
      <button id="helpBtn" class="btn mono" title="Help / Quick Start" style="padding:9px 12px">?</button>
      <button id="gearBtn" class="btn mono" title="Settings" style="padding:9px 11px">⚙</button>
    </div>
  </div>
  <div class="wrap" style="padding-top:0;padding-bottom:14px">
    <div id="modeSel" style="display:inline-flex;gap:0;border:1px solid var(--line2);border-radius:10px;overflow:hidden">
      <button class="modebtn active mono" data-mode="survey">◈ SURVEY</button>
      <button class="modebtn mono" data-mode="finder">◎ FINDER</button>
      <button class="modebtn mono" data-mode="sweep">◭ SWEEP</button>
    </div>
    <span id="modeHint" class="mono" style="margin-left:14px;font-size:11.5px;color:var(--muted)"></span>
  </div>
  <div class="statbar">
    <div class="stat"><div class="l mono">EMITTERS</div><div class="v" id="s-total">0</div></div>
    <div class="stat"><div class="l mono">WI-FI</div><div class="v" id="s-wifi">0</div></div>
    <div class="stat"><div class="l mono">BLE</div><div class="v" id="s-ble">0</div></div>
    <div class="stat"><div class="l mono">RANDOMIZED</div><div class="v" id="s-rnd">0</div></div>
    <div class="stat"><div class="l mono">SWEEPS</div><div class="v" id="s-sweep">0</div></div>
  </div>
</header>

<div id="toast" class="toast" style="display:none"><div class="in"></div></div>

<main>
  <div id="finderPanel" class="card" style="display:none;margin-bottom:22px;border-color:#4FD6A055">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap;gap:10px">
      <div style="display:flex;align-items:center;gap:10px">
        <span class="mono" style="font-size:13px;letter-spacing:2px;color:#4FD6A0">◎ FINDER — LOCATE YOUR DEVICES</span>
        <span id="finderCount" class="mono" style="font-size:11px;color:var(--muted)"></span>
      </div>
      <button id="finderManage" class="btn mono" style="padding:6px 12px">MANAGE ALLOWLIST</button>
    </div>
    <div id="finderBody" style="padding:18px"></div>
  </div>

  <div id="sweepPanel" class="card" style="display:none;margin-bottom:22px;border-color:#FF547055">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap;gap:10px">
      <div style="display:flex;align-items:center;gap:10px">
        <span class="mono" style="font-size:13px;letter-spacing:2px;color:#FF5470">◭ SWEEP — FIND WHAT SHOULDN'T BE HERE</span>
        <span id="sweepCount" class="mono" style="font-size:11px;color:var(--muted)"></span>
      </div>
      <button id="sweepManage" class="btn mono" style="padding:6px 12px">MANAGE BLOCKLIST</button>
    </div>
    <div id="sweepBody" style="padding:18px"></div>
  </div>

  <div class="grid">
    <div>
      <div class="card pad">
        <div class="fieldhead">
          <span class="l mono">PROXIMITY FIELD</span>
          <span class="r mono">radius = signal · bearing not measured</span>
        </div>
        <div id="field"></div>
        <div class="legend">
          <span class="leg mono"><span style="width:10px;height:10px;border-radius:50%;background:rgb(255,122,69)"></span>strong</span>
          <span class="leg mono"><span style="width:34px;height:8px;border-radius:4px;background:linear-gradient(90deg,rgb(255,122,69),rgb(40,194,180),rgb(104,78,224))"></span>weak</span>
          <span class="leg mono"><span style="width:11px;height:11px;border-radius:50%;background:var(--mid)"></span>Wi-Fi</span>
          <span class="leg mono"><span style="width:9px;height:9px;background:var(--mid);transform:rotate(45deg);display:inline-block"></span>BLE</span>
          <span class="leg mono"><span style="width:10px;height:10px;border-radius:50%;border:1.5px dashed var(--hot)"></span>randomized</span>
        </div>
      </div>

      <div class="card" style="margin-top:18px;overflow:hidden">
        <div class="chips" id="chips">
          <button class="chip active mono" data-f="all">ALL <span class="c" id="c-all">0</span></button>
          <button class="chip mono" data-f="wifi">WI-FI <span class="c" id="c-wifi">0</span></button>
          <button class="chip mono" data-f="ble">BLE <span class="c" id="c-ble">0</span></button>
          <button class="chip mono" data-f="randomized">RANDOMIZED <span class="c" id="c-rnd">0</span></button>
        </div>
        <div class="ledhead" id="ledhead">
          <button data-k="rssi_median" style="width:18%">SIG</button>
          <button style="width:8%" data-k=""></button>
          <button data-k="label" style="width:34%">EMITTER</button>
          <button data-k="range_m" style="width:20%">RANGE</button>
          <button data-k="sightings" style="width:20%">SEEN</button>
        </div>
        <div class="ledbody" id="ledbody"></div>
      </div>
    </div>

    <div class="card detail" id="detail"></div>
  </div>

  <div class="card" id="rfcard" style="margin-top:22px">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap;gap:10px">
      <div style="display:flex;align-items:center;gap:12px">
        <span class="mono" style="font-size:12px;letter-spacing:2px;color:var(--mid)">RF SPECTRUM</span>
        <span id="sdrPill" class="mono" style="font-size:10px;letter-spacing:1px;padding:3px 8px;border-radius:6px;background:var(--panel2);border:1px solid var(--line2);color:var(--muted)">checking SDR…</span>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <label class="mono" style="font-size:11px;color:var(--mid);display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="simToggle" checked style="accent-color:var(--amber)"> simulate</label>
        <button id="rfScanBtn" class="btn primary mono" style="padding:7px 12px">▚ SCAN</button>
      </div>
    </div>
    <div style="padding:14px 18px 0;display:flex;gap:7px;flex-wrap:wrap" id="rfPresets"></div>
    <div style="padding:14px 18px 4px">
      <canvas id="analyzer" style="width:100%;height:150px;display:block;border-radius:8px;background:var(--ink2)"></canvas>
      <div style="display:flex;justify-content:space-between;margin-top:4px" class="mono" id="analyzerAxis" style="font-size:10px;color:var(--muted)"></div>
    </div>
    <div style="padding:8px 18px 4px">
      <div class="mono" style="font-size:10px;letter-spacing:2px;color:var(--muted);margin-bottom:6px">WATERFALL <span style="color:var(--line2)">— time flows down, colour = power</span></div>
      <canvas id="waterfall" style="width:100%;height:180px;display:block;border-radius:8px;background:var(--ink2)"></canvas>
    </div>
    <div id="rfPeaks" style="padding:12px 18px 20px"></div>
  </div>

  <div class="card" style="margin-top:22px">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap;gap:10px">
      <span class="mono" style="font-size:12px;letter-spacing:2px;color:var(--mid)">SURFACE INTELLIGENCE</span>
      <div style="display:flex;gap:8px;align-items:center">
        <button id="refreshAnalysis" class="btn mono" style="padding:7px 12px">RE-ANALYZE</button>
        <button id="aiBtn" class="btn primary mono" style="padding:7px 12px">✦ AI ASSESSMENT</button>
      </div>
    </div>
    <div id="analysis" style="padding:4px 18px 20px"></div>
    <div id="aibox" style="display:none;margin:0 18px 20px;padding:16px 18px;background:var(--ink2);border:1px solid var(--line2);border-radius:12px"></div>
  </div>

  <footer>
    Range is a log-distance estimate from RSSI — an order-of-magnitude bucket, not a coordinate.
    Bearing is not shown because a passive single antenna can't measure direction.
    Randomized emitters are marked because they don't persist across sessions.
  </footer>
</main>

<div id="modal" style="display:none;position:fixed;inset:0;background:rgba(5,7,14,.72);backdrop-filter:blur(4px);z-index:50;align-items:flex-start;justify-content:center;padding:60px 20px;overflow-y:auto">
  <div style="width:100%;max-width:520px;background:var(--panel);border:1px solid var(--line2);border-radius:16px;box-shadow:0 24px 80px rgba(0,0,0,.6)">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line)">
      <span class="mono" style="font-size:13px;letter-spacing:2px;color:var(--hi)">SETTINGS</span>
      <button id="modalClose" class="btn" style="padding:6px;line-height:0">X</button>
    </div>
    <div style="padding:20px">
      <div class="mono" style="font-size:10.5px;letter-spacing:2px;color:var(--muted);margin-bottom:8px">ANTHROPIC API KEY</div>
      <div style="font-size:12.5px;color:var(--mid);line-height:1.5;margin-bottom:10px">Enables the AI assessment of your surface. Stored in server memory for this session; tick "save to disk" to persist to <span class="mono" style="color:var(--txt)">~/.spectra/config.json</span> (chmod 600).</div>
      <input id="keyInput" type="password" placeholder="sk-ant-..." class="mono" style="width:100%;background:var(--ink2);border:1px solid var(--line2);border-radius:8px;color:var(--txt);padding:10px 12px;font-size:12.5px">
      <div id="keyStatus" class="mono" style="font-size:11px;color:var(--mid);margin-top:8px"></div>
      <label class="mono" style="font-size:11.5px;color:var(--mid);display:flex;align-items:center;gap:8px;margin-top:12px;cursor:pointer"><input type="checkbox" id="persistKey" style="accent-color:var(--amber)"> save to disk (persists across restarts)</label>
      <div style="display:flex;gap:8px;margin-top:16px">
        <button id="keySave" class="btn primary mono" style="flex:1;justify-content:center">SAVE KEY</button>
        <button id="keyClear" class="btn stop mono" style="justify-content:center">CLEAR</button>
      </div>
      <div style="margin-top:18px;padding:12px 14px;background:var(--ink2);border:1px solid var(--line);border-radius:10px;font-size:11.5px;color:var(--muted);line-height:1.6">
        <span class="mono" style="color:var(--mid)">SDR STATUS</span><br>
        <span id="modalSdr">checking...</span>
      </div>
      <div style="margin-top:12px;font-size:11px;color:var(--muted);line-height:1.6">This is a local tool. Don't expose it to a network with a key saved to disk.</div>
    </div>
  </div>
</div>

<div id="wlModal" style="display:none;position:fixed;inset:0;background:rgba(5,7,14,.72);backdrop-filter:blur(4px);z-index:50;align-items:flex-start;justify-content:center;padding:50px 20px;overflow-y:auto">
  <div style="width:100%;max-width:600px;background:var(--panel);border:1px solid var(--line2);border-radius:16px;box-shadow:0 24px 80px rgba(0,0,0,.6)">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line)">
      <span class="mono" style="font-size:13px;letter-spacing:2px;color:var(--hi)" id="wlTitle">WATCHLIST</span>
      <button id="wlClose" class="btn" style="padding:6px;line-height:0">X</button>
    </div>
    <div style="padding:20px">
      <div style="display:flex;gap:0;border:1px solid var(--line2);border-radius:9px;overflow:hidden;margin-bottom:16px;width:fit-content">
        <button class="wltab active mono" data-wl="allow">ALLOW (mine)</button>
        <button class="wltab mono" data-wl="block">BLOCK (hunt)</button>
      </div>
      <div class="mono" style="font-size:12.5px;color:var(--mid);line-height:1.5;margin-bottom:10px" id="wlDesc"></div>
      <textarea id="wlText" placeholder="Paste MACs - one per line. CSV ok:&#10;AA:BB:CC:DD:EE:FF, Backpack sticker&#10;aabbccdd0011, Wallet&#10;11-22-33-44-55-66" class="mono" style="width:100%;height:110px;background:var(--ink2);border:1px solid var(--line2);border-radius:8px;color:var(--txt);padding:10px 12px;font-size:12px;resize:vertical"></textarea>
      <div style="display:flex;gap:8px;margin:10px 0">
        <button id="wlImport" class="btn primary mono" style="flex:1;justify-content:center">IMPORT LIST</button>
        <label class="btn mono" style="cursor:pointer;justify-content:center" for="wlFile">UPLOAD FILE</label>
        <input id="wlFile" type="file" accept=".txt,.csv,text/plain" style="display:none">
      </div>
      <div id="wlList" style="margin-top:14px;max-height:240px;overflow-y:auto"></div>
      <button id="wlClear" class="btn stop mono" style="margin-top:12px;justify-content:center;width:100%">CLEAR THIS LIST</button>
    </div>
  </div>
</div>

<div id="helpModal" style="display:none;position:fixed;inset:0;background:rgba(5,7,14,.75);backdrop-filter:blur(4px);z-index:50;align-items:flex-start;justify-content:center;padding:40px 20px;overflow-y:auto">
  <div style="width:100%;max-width:720px;background:var(--panel);border:1px solid var(--line2);border-radius:16px;box-shadow:0 24px 80px rgba(0,0,0,.6)">
    <div style="display:flex;justify-content:space-between;align-items:center;padding:18px 20px;border-bottom:1px solid var(--line)">
      <span class="mono" style="font-size:13px;letter-spacing:2px;color:var(--hi)">SPECTRA - HELP &amp; QUICK START</span>
      <button id="helpClose" class="btn" style="padding:6px;line-height:0">X</button>
    </div>
    <div style="display:flex;gap:0;border-bottom:1px solid var(--line);padding:0 12px;overflow-x:auto" id="helpTabs">
      <button class="helptab active mono" data-h="start">QUICK START</button>
      <button class="helptab mono" data-h="finder">FINDER</button>
      <button class="helptab mono" data-h="sweep">SWEEP</button>
      <button class="helptab mono" data-h="rf">RF / SDR</button>
      <button class="helptab mono" data-h="hardware">HARDWARE</button>
      <button class="helptab mono" data-h="honest">LIMITS</button>
    </div>
    <div id="helpBody" style="padding:22px;font-size:13.5px;line-height:1.65;color:var(--txt);max-height:60vh;overflow-y:auto"></div>
  </div>
</div>

<script>
// ---- design tokens mirrored for canvas/SVG use ----
const C = getComputedStyle(document.documentElement);
const HOT="#FF7A45", AMBER="#F2B33D", MID="#8A93B4", MUTED="#646E92", LINE="#232B4A", LINE2="#2E3860", HI="#F2F5FF";

// ---- math (identical to spectra.py's model) ----
const RAMP=[[0,[104,78,224]],[0.3,[37,150,214]],[0.55,[40,194,180]],[0.78,[242,179,61]],[1,[255,122,69]]];
const lerp=(a,b,t)=>a+(b-a)*t;
function rampColor(t){t=Math.max(0,Math.min(1,t));for(let i=0;i<RAMP.length-1;i++){const[t0,c0]=RAMP[i],[t1,c1]=RAMP[i+1];if(t>=t0&&t<=t1){const k=(t-t0)/(t1-t0);return `rgb(${Math.round(lerp(c0[0],c1[0],k))},${Math.round(lerp(c0[1],c1[1],k))},${Math.round(lerp(c0[2],c1[2],k))})`;}}const l=RAMP[RAMP.length-1][1];return `rgb(${l[0]},${l[1]},${l[2]})`;}
const rssiT=r=>r==null?0:Math.max(0,Math.min(1,(r- -95)/(-40- -95)));
const signalColor=r=>rampColor(rssiT(r));
function addrAngle(a){let h=2166136261;for(let i=0;i<a.length;i++){h^=a.charCodeAt(i);h=Math.imul(h,16777619);}return((h>>>0)%3600)/10;}
const R_MIN=0.5,R_MAX=130;
const rangeNorm=m=>m==null?1:Math.max(0,Math.min(1,Math.log(Math.max(R_MIN,Math.min(R_MAX,m))/R_MIN)/Math.log(R_MAX/R_MIN)));
const RINGS=[{l:"IMMEDIATE",s:"<2m",m:2},{l:"NEAR",s:"2–8m",m:8},{l:"MID",s:"8–25m",m:25},{l:"FAR",s:">25m",m:R_MAX}];
function fmtTime(iso){if(!iso)return "—";try{return new Date(iso).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});}catch(e){return iso;}}
const esc=s=>(s==null?"":String(s)).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

// ---- state ----
let STATE={surface:[],filter:"all",selected:null,sortKey:"rssi_median",sortDir:"desc",running:false,sweep:0};

// ---- field render ----
function renderField(){
  const size=520,cx=size/2,cy=size/2,rInner=34,rOuter=size/2-30;
  const ringR=n=>rInner+(rOuter-rInner)*n;
  const rows=visibleRows();
  let s=`<svg viewBox="0 0 ${size} ${size}" width="100%" style="display:block;max-height:560px">`;
  s+=`<defs><radialGradient id="fg" cx="50%" cy="50%" r="50%">
    <stop offset="0%" stop-color="rgba(255,122,69,.10)"/><stop offset="30%" stop-color="rgba(242,179,61,.06)"/>
    <stop offset="62%" stop-color="rgba(40,194,180,.05)"/><stop offset="100%" stop-color="rgba(104,78,224,.04)"/>
   </radialGradient></defs>`;
  s+=`<circle cx="${cx}" cy="${cy}" r="${rOuter}" fill="url(#fg)"/>`;
  RINGS.forEach((r,i)=>{const rr=ringR(rangeNorm(r.m));
    s+=`<circle cx="${cx}" cy="${cy}" r="${rr}" fill="none" stroke="${LINE}" stroke-width="1" ${i===RINGS.length-1?'stroke-dasharray="2 4"':''}/>`;
    s+=`<text x="${cx}" y="${cy-rr-4}" fill="${MUTED}" font-size="9" font-family="'JetBrains Mono',monospace" text-anchor="middle" letter-spacing="1.5">${r.l} · ${r.s}</text>`;});
  s+=`<line x1="${cx-8}" y1="${cy}" x2="${cx+8}" y2="${cy}" stroke="${LINE2}"/><line x1="${cx}" y1="${cy-8}" x2="${cx}" y2="${cy+8}" stroke="${LINE2}"/>`;
  if(STATE.running){
    s+=`<circle class="ping" cx="${cx}" cy="${cy}" r="${rInner}" fill="none" stroke="${AMBER}" stroke-width="1.5" opacity="0">
      <animate attributeName="r" values="${rInner};${rOuter}" dur="3.2s" repeatCount="indefinite"/>
      <animate attributeName="opacity" values="0.5;0" dur="3.2s" repeatCount="indefinite"/></circle>`;
  }
  s+=`<circle cx="${cx}" cy="${cy}" r="5" fill="${HI}"/><text x="${cx}" y="${cy+20}" fill="${MID}" font-size="9" font-family="'JetBrains Mono',monospace" text-anchor="middle" letter-spacing="2">RECEIVER</text>`;
  rows.forEach(r=>{
    const norm=rangeNorm(r.range_m),rad=ringR(norm),ang=addrAngle(r.addr)*Math.PI/180;
    const x=cx+rad*Math.cos(ang),y=cy+rad*Math.sin(ang),col=signalColor(r.rssi_median);
    const sel=STATE.selected===r.addr,rr=sel?9:7;
    if(sel)s+=`<circle cx="${x}" cy="${y}" r="16" fill="${col}" opacity="0.18"/>`;
    if(r.band==="ble"){
      s+=`<rect data-addr="${esc(r.addr)}" x="${x-rr}" y="${y-rr}" width="${rr*2}" height="${rr*2}" transform="rotate(45 ${x} ${y})" fill="${r.randomized?'none':col}" stroke="${col}" stroke-width="${r.randomized?1.6:1}" ${r.randomized?'stroke-dasharray="2 2"':''} style="cursor:pointer"/>`;
    }else{
      s+=`<circle data-addr="${esc(r.addr)}" cx="${x}" cy="${y}" r="${rr}" fill="${r.randomized?'none':col}" stroke="${col}" stroke-width="${r.randomized?1.6:1}" ${r.randomized?'stroke-dasharray="2 2"':''} style="cursor:pointer"/>`;
    }
    if(sel)s+=`<text x="${x}" y="${y-14}" fill="${HI}" font-size="10" font-family="'JetBrains Mono',monospace" text-anchor="middle">${esc(r.label||r.addr.slice(0,8))}</text>`;
  });
  s+=`</svg>`;
  const el=document.getElementById("field");el.innerHTML=s;
  el.querySelectorAll("[data-addr]").forEach(n=>n.addEventListener("click",()=>select(n.getAttribute("data-addr"))));
}

// ---- ledger ----
function visibleRows(){
  let r=STATE.surface.slice();
  if(STATE.filter==="wifi")r=r.filter(x=>x.band==="wifi");
  else if(STATE.filter==="ble")r=r.filter(x=>x.band==="ble");
  else if(STATE.filter==="randomized")r=r.filter(x=>x.randomized);
  const dir=STATE.sortDir==="desc"?-1:1,k=STATE.sortKey;
  r.sort((a,b)=>{
    if(k==="label"||k==="band")return String(a[k]||"").localeCompare(String(b[k]||""))*dir;
    return (((a[k]??-999)-(b[k]??-999)))*dir;
  });
  return r;
}
function renderLedger(){
  const rows=visibleRows(),body=document.getElementById("ledbody");
  if(!rows.length){body.innerHTML=`<div style="padding:34px 14px;text-align:center;color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:12.5px">No emitters in view.<br>Run a sweep, or clear the filter.</div>`;return;}
  body.innerHTML=rows.map(r=>{
    const col=signalColor(r.rssi_median),sel=STATE.selected===r.addr;
    const icon=r.band==="wifi"?"WiFi":"BLE";
    const vend=(r.vendor&&r.vendor!=="(randomized — no vendor)")?r.vendor:r.addr;
    const seen=r.randomized?`<span style="color:${HOT}">${r.sightings}× rnd</span>`:`${r.sightings}×`;
    return `<button class="row ${sel?'sel':''}" data-addr="${esc(r.addr)}" style="${sel?`border-left-color:${col}`:''}">
      <span style="width:18%;display:flex;align-items:center;gap:8px">
        <span style="width:9px;height:9px;border-radius:50%;background:${r.randomized?'transparent':col};border:1.5px solid ${col};flex-shrink:0"></span>
        <span class="mono" style="font-size:12.5px;color:${HI}">${r.rssi_median??'—'}</span></span>
      <span style="width:8%;font-size:10px;letter-spacing:1px;color:${MID}" class="mono">${icon}</span>
      <span style="width:34%;overflow:hidden">
        <span style="display:block;font-size:13.5px;color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${r.label?esc(r.label):'<span style=\"color:'+MUTED+'\">— hidden</span>'}</span>
        <span class="mono" style="display:block;font-size:10.5px;color:${MUTED};white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(vend)}</span></span>
      <span class="mono" style="width:20%;font-size:12.5px;color:${MID}">${r.range_m!=null?'~'+r.range_m+'m':'—'}</span>
      <span class="mono" style="width:20%;font-size:12.5px;color:${MID}">${seen}</span>
    </button>`;
  }).join("");
  body.querySelectorAll(".row").forEach(n=>n.addEventListener("click",()=>select(n.getAttribute("data-addr"))));
}

// ---- detail ----
function rangeBar(lo,mid,hi){
  if(mid==null)return `<span style="color:${MUTED}">n/a</span>`;
  const a=rangeNorm(lo??mid)*100,b=rangeNorm(hi??mid)*100,m=rangeNorm(mid)*100;
  return `<div><div style="position:relative;height:8px;background:var(--panel2);border-radius:4px;overflow:hidden">
    <div style="position:absolute;left:${a}%;width:${Math.max(2,b-a)}%;top:0;bottom:0;background:rgba(242,179,61,.28)"></div>
    <div style="position:absolute;left:${m}%;top:-2px;bottom:-2px;width:2px;background:${AMBER}"></div></div>
    <div class="mono" style="display:flex;justify-content:space-between;margin-top:4px;font-size:11px;color:${MID}"><span>~${mid}m</span><span>plausible ${lo}–${hi}m</span></div></div>`;
}
function sparkline(series,col){
  if(!series||series.length<2)return "";
  const w=220,h=46,mn=Math.min(...series)-2,mx=Math.max(...series)+2;
  const pts=series.map((v,i)=>`${(i/(series.length-1)*w).toFixed(1)},${(h-(v-mn)/(mx-mn)*h).toFixed(1)}`);
  let dots=series.map((v,i)=>`<circle cx="${(i/(series.length-1)*w).toFixed(1)}" cy="${(h-(v-mn)/(mx-mn)*h).toFixed(1)}" r="2" fill="${col}"/>`).join("");
  return `<svg width="${w}" height="${h}" style="display:block"><polyline points="${pts.join(' ')}" fill="none" stroke="${col}" stroke-width="1.6"/>${dots}</svg>`;
}
function renderDetail(){
  const el=document.getElementById("detail");
  const r=STATE.surface.find(x=>x.addr===STATE.selected);
  if(!r){
    el.innerHTML=`<div class="empty"><div style="font-size:30px;color:${LINE2}">✛</div>
      <div style="margin-top:14px;font-size:14px;color:var(--txt)">Select an emitter</div>
      <div style="margin-top:8px;font-size:12.5px;line-height:1.6;color:${MUTED}">Tap a point in the field or a row in the ledger to read its full telemetry — vendor, security, range with error bars, and signal trend.</div>
      <div class="kbox" style="margin-top:20px;text-align:left">
        <div class="mono" style="color:${MUTED};letter-spacing:1px;font-size:11px;margin-bottom:6px">K-ANONYMITY CHECK</div>
        <div style="font-size:12px;color:var(--mid);line-height:1.5">Range-query a secret against HIBP. Only a 5-char hash prefix leaves this machine.</div>
        <input id="kin" placeholder="secret to check" class="mono"/>
        <button class="btn mono" id="kbtn" style="width:100%;justify-content:center">CHECK</button>
        <div class="kres" id="kres" style="margin-top:10px"></div>
      </div></div>`;
    wireKanon();return;
  }
  const col=signalColor(r.rssi_median);
  el.innerHTML=`<div class="d-pad">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
      <div>
        <div class="mono" style="display:flex;align-items:center;gap:8px;color:${MID};font-size:11px;letter-spacing:2px;text-transform:uppercase">${r.band==="wifi"?"Wi-Fi access point":r.band==="ble"?"BLE advertiser":"emitter"}</div>
        <div class="mono" style="font-size:18px;color:${HI};margin-top:6px;letter-spacing:.5px">${esc(r.addr)}</div>
        <div style="font-size:15px;color:var(--txt);margin-top:2px">${r.label?esc(r.label):'<span style=\"color:'+MUTED+'\">hidden / unnamed</span>'}</div>
      </div>
      <button class="btn" id="dclose" style="padding:6px;line-height:0">✕</button>
    </div>
    ${r.randomized?`<div class="warn"><span style="color:${HOT};flex-shrink:0">⚠</span><div><b style="color:${HOT}">Randomized address.</b> Not a stable identifier — it rotates on the device's own schedule. Don't count it as one device across sweeps or attribute a vendor to it.</div></div>`:''}
    <div style="margin-top:20px">
      <div class="frow"><span class="k">Signal (median)</span><span class="val"><span style="display:inline-flex;align-items:center;gap:8px"><span style="width:10px;height:10px;border-radius:50%;background:${col}"></span><b class="mono" style="color:${HI}">${r.rssi_median} dBm</b><span class="mono" style="color:${MUTED}">± ${r.rssi_stdev}</span></span></span></div>
      <div style="margin:14px 0"><div class="mono" style="font-size:10.5px;letter-spacing:2px;color:${MUTED};text-transform:uppercase;margin-bottom:8px">Estimated range</div>${rangeBar(r.range_low_m,r.range_m,r.range_high_m)}</div>
      ${r.rssi_series?`<div style="margin:16px 0"><div class="mono" style="font-size:10.5px;letter-spacing:2px;color:${MUTED};text-transform:uppercase;margin-bottom:8px">RSSI across sweeps</div>${sparkline(r.rssi_series,col)}</div>`:''}
      <div class="frow"><span class="k">Vendor (OUI)</span><span class="val">${r.vendor?esc(r.vendor):'—'}</span></div>
      ${r.ble_hint?`<div class="frow"><span class="k">BLE identity</span><span class="val" style="color:var(--good)">${esc(r.ble_hint)}</span></div>`:''}
      ${r.band==="wifi"?`<div class="frow"><span class="k">Security</span><span class="val">${esc(r.security)||'—'}</span></div><div class="frow"><span class="k">Channel</span><span class="val">${esc(r.channel)||'—'}</span></div>`:''}
      <div class="frow"><span class="k">Sightings</span><span class="val">${r.sightings}×</span></div>
      <div class="frow"><span class="k">Identifier</span><span class="val">${r.randomized?`<span style="color:${HOT}">unstable (randomized)</span>`:`<span style="color:var(--good)">stable</span>`}</span></div>
      <div class="frow"><span class="k">First → last</span><span class="val mono" style="font-size:12px">${fmtTime(r.first_seen)} → ${fmtTime(r.last_seen)}</span></div>
      <div style="display:flex;gap:8px;margin-top:14px">
        <button class="btn mono" style="flex:1;justify-content:center;font-size:11px" onclick="tagDevice('${esc(r.addr)}','allow')">+ ALLOWLIST</button>
        <button class="btn mono" style="flex:1;justify-content:center;font-size:11px" onclick="tagDevice('${esc(r.addr)}','block')">+ BLOCKLIST</button>
      </div>
      ${r.watch&&r.watch!=='unknown'?`<div class="mono" style="font-size:11px;color:${r.watch==='allow'?'#4FD6A0':'#FF5470'};margin-top:8px;text-align:center">● on ${r.watch}list${r.watch_label?' — '+esc(r.watch_label):''}</div>`:''}
    </div></div>`;
  document.getElementById("dclose").addEventListener("click",()=>select(null));
}
function wireKanon(){
  const btn=document.getElementById("kbtn");if(!btn)return;
  btn.addEventListener("click",async()=>{
    const secret=document.getElementById("kin").value;const out=document.getElementById("kres");
    if(!secret){out.textContent="enter a secret first";return;}
    out.textContent="querying…";
    try{
      const res=await fetch("/api/kanon",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({secret})});
      const d=await res.json();
      if(d.error){out.textContent=d.error;return;}
      out.innerHTML=`prefix sent : <span style="color:${AMBER}">${d.prefix_sent}</span>\nbucket (k)  : ${d.bucket_size_k}\nfound       : <span style="color:${d.found?HOT:'var(--good)'}">${d.found}</span>\noccurrences : ${d.occurrences.toLocaleString()}\nleaked      : ${d.bytes_leaked_to_server} bytes\n\nThe server saw only the prefix. Your query hid among ${d.bucket_size_k} candidates.`;
    }catch(e){out.textContent="lookup failed: "+e.message;}
  });
}

// ---- stats & chrome ----
function renderStats(){
  const d=STATE.surface;
  const wifi=d.filter(x=>x.band==="wifi").length,ble=d.filter(x=>x.band==="ble").length,rnd=d.filter(x=>x.randomized).length;
  document.getElementById("s-total").textContent=d.length;
  document.getElementById("s-wifi").textContent=wifi;
  document.getElementById("s-ble").textContent=ble;
  const rEl=document.getElementById("s-rnd");rEl.textContent=rnd;rEl.style.color=rnd?HOT:HI;
  document.getElementById("s-sweep").textContent=STATE.sweep;
  document.getElementById("c-all").textContent=d.length;
  document.getElementById("c-wifi").textContent=wifi;
  document.getElementById("c-ble").textContent=ble;
  document.getElementById("c-rnd").textContent=rnd;
  const dot=document.getElementById("livedot"),txt=document.getElementById("livetext"),lb=document.getElementById("liveBtn");
  if(STATE.running){dot.classList.add("on");txt.textContent="LIVE";lb.textContent="STOP";lb.classList.remove("primary");lb.classList.add("stop");}
  else{dot.classList.remove("on");txt.textContent="IDLE";lb.textContent="START LIVE";lb.classList.add("primary");lb.classList.remove("stop");}
}
function renderAll(){renderStats();renderField();renderLedger();renderDetail();}
function select(addr){STATE.selected=(addr===STATE.selected)?null:addr;renderAll();}

// ---- controls ----
document.getElementById("chips").addEventListener("click",e=>{
  const b=e.target.closest(".chip");if(!b)return;
  STATE.filter=b.getAttribute("data-f");
  document.querySelectorAll(".chip").forEach(c=>c.classList.toggle("active",c===b));
  renderField();renderLedger();
});
document.getElementById("ledhead").addEventListener("click",e=>{
  const b=e.target.closest("button");if(!b)return;const k=b.getAttribute("data-k");if(!k)return;
  if(k===STATE.sortKey)STATE.sortDir=STATE.sortDir==="desc"?"asc":"desc";else{STATE.sortKey=k;STATE.sortDir="desc";}
  document.querySelectorAll("#ledhead button").forEach(x=>x.classList.toggle("act",x===b));
  renderLedger();
});
function toast(msg,ok){const t=document.getElementById("toast");t.style.display="block";t.querySelector(".in").className="in "+(ok?"ok":"err");t.querySelector(".in").textContent=msg;setTimeout(()=>t.style.display="none",4200);}
document.getElementById("sweepBtn").addEventListener("click",async()=>{
  const b=document.getElementById("sweepBtn");b.textContent="SWEEPING…";b.disabled=true;
  try{const res=await fetch("/api/sweep",{method:"POST"});const d=await res.json();
    STATE.surface=d.surface;STATE.sweep=d.state.sweep_count;STATE.running=d.state.running;renderAll();
    toast(`sweep complete — ${d.observations} observations`,true);
  }catch(e){toast("sweep failed: "+e.message,false);}
  b.textContent="SWEEP ONCE";b.disabled=false;
});
document.getElementById("liveBtn").addEventListener("click",async()=>{
  const action=STATE.running?"stop":"start";
  try{const res=await fetch("/api/control",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action})});
    const st=await res.json();STATE.running=st.running;renderStats();renderField();
  }catch(e){toast("control failed: "+e.message,false);}
});

// ---- live stream ----
let connect=function(){
  const es=new EventSource("/api/stream");
  es.onmessage=ev=>{
    let d;try{d=JSON.parse(ev.data);}catch(e){return;}
    if(d.surface)STATE.surface=d.surface;
    if(typeof d.running==="boolean")STATE.running=d.running;
    if(d.sweep!=null)STATE.sweep=d.sweep;
    if(d.state&&d.state.sweep_count!=null)STATE.sweep=d.state.sweep_count;
    if(d.type==="error")toast("radio: "+d.message,false);
    if(d.type==="sweep")toast(`sweep ${d.sweep} — ${d.observations} observations`,true);
    renderAll();
    if(d.type==="sweep"||d.type==="snapshot")loadAnalysis();
  };
  es.onerror=()=>{/* browser auto-reconnects */};
};

// ---- surface intelligence ----
function pill(text,color){return `<span class="mono" style="display:inline-block;padding:2px 8px;border-radius:6px;font-size:11px;background:${color}22;border:1px solid ${color}55;color:${color};margin:2px 4px 2px 0">${text}</span>`;}
function bar(segments){ // segments: [{label,count,color}]
  const total=segments.reduce((s,x)=>s+x.count,0)||1;
  let out=`<div style="display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--panel2)">`;
  segments.forEach(s=>{if(s.count)out+=`<div title="${s.label}: ${s.count}" style="width:${s.count/total*100}%;background:${s.color}"></div>`;});
  out+=`</div><div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:8px">`;
  segments.forEach(s=>{if(s.count)out+=`<span class="mono" style="font-size:11px;color:var(--mid)"><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${s.color};margin-right:5px"></span>${s.label} ${s.count}</span>`;});
  return out+`</div>`;
}
const SEC_COLORS={wpa3:"#4FD6A0","wpa2/3-transition":"#7CC7E8",wpa2:"#F2B33D",wpa:"#FF9E4A",wep:"#FF7A45",open:"#FF5470",other:"#646E92"};
const BAND_COLORS={"2.4 GHz":"#FF9E4A","5 GHz":"#4FD6A0","6 GHz":"#7CC7E8","unknown":"#646E92"};
const LVL={high:"#FF5470",warn:"#F2B33D",info:"#7CC7E8"};

function renderAnalysis(a){
  const el=document.getElementById("analysis");
  const d=a.devices;
  const secSeg=Object.entries(a.security.counts).map(([k,v])=>({label:k,count:v,color:SEC_COLORS[k]||"#646E92"}));
  const bandSeg=Object.entries(a.channels.bands).map(([k,v])=>({label:k,count:v,color:BAND_COLORS[k]||"#646E92"}));
  let html=`<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;margin-top:16px">`;

  // devices
  html+=`<div><div class="mono" style="font-size:10.5px;letter-spacing:2px;color:var(--muted);margin-bottom:10px">PHYSICAL DEVICES</div>
    <div style="font-size:26px;font-weight:600;color:var(--hi)">${d.device_estimate}<span style="font-size:14px;color:var(--mid);font-weight:400"> devices</span></div>
    <div class="mono" style="font-size:11.5px;color:var(--mid);margin-top:2px">${d.bssid_count} BSSIDs → ${d.radio_count} radios → ${d.device_estimate} devices · ${d.collapse_ratio}× collapse</div>
    <div style="margin-top:12px;max-height:150px;overflow-y:auto">`;
  d.devices.slice(0,8).forEach(dev=>{
    const col=signalColor(dev.rssi);
    html+=`<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--line)">
      <span style="width:8px;height:8px;border-radius:50%;background:${col};flex-shrink:0"></span>
      <span style="flex:1;font-size:12.5px;color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(dev.ssids[0]||dev.vendor||dev.oui)||'<span style=\"color:'+MUTED+'\">hidden</span>'}</span>
      <span class="mono" style="font-size:11px;color:var(--mid)">${dev.bssid_count}bssid</span>
      <span class="mono" style="font-size:11px;color:${col}">${dev.rssi??'—'}</span>
      ${dev.confidence==='medium'?pill('~','#F2B33D'):''}</div>`;
  });
  html+=`</div></div>`;

  // security
  html+=`<div><div class="mono" style="font-size:10.5px;letter-spacing:2px;color:var(--muted);margin-bottom:10px">SECURITY POSTURE</div>${bar(secSeg)}`;
  if(a.security.weak.length){html+=`<div style="margin-top:12px">`;a.security.weak.slice(0,4).forEach(w=>{html+=`<div style="font-size:12px;color:var(--txt);padding:3px 0">${pill(w.class.toUpperCase(),SEC_COLORS[w.class]||'#FF5470')} ${esc(w.label)} <span class="mono" style="color:var(--mid)">${w.rssi}dBm</span></div>`;});html+=`</div>`;}
  html+=`</div>`;

  // bands / congestion
  html+=`<div><div class="mono" style="font-size:10.5px;letter-spacing:2px;color:var(--muted);margin-bottom:10px">BANDS &amp; CONGESTION</div>${bar(bandSeg)}`;
  if(a.channels.busiest_24ghz.length){html+=`<div class="mono" style="font-size:11.5px;color:var(--mid);margin-top:12px">2.4 GHz load: `+a.channels.busiest_24ghz.map(([c,n])=>`ch${c} <span style="color:${n>=4?'#FF9E4A':'var(--txt)'}">${n}</span>`).join(" · ")+`</div>`;}
  html+=`</div>`;

  html+=`</div>`; // end grid

  // anomalies
  if(a.anomalies.length){
    html+=`<div style="margin-top:20px"><div class="mono" style="font-size:10.5px;letter-spacing:2px;color:var(--muted);margin-bottom:10px">FLAGS</div>`;
    a.anomalies.forEach(an=>{const c=LVL[an.level]||MUTED;
      html+=`<div style="display:flex;gap:10px;align-items:flex-start;padding:7px 0;border-bottom:1px solid var(--line)">
        <span class="mono" style="font-size:9.5px;letter-spacing:1px;color:${c};border:1px solid ${c}66;border-radius:5px;padding:2px 6px;flex-shrink:0;margin-top:1px">${an.level.toUpperCase()}</span>
        <span style="font-size:12.5px;color:var(--txt);line-height:1.5">${esc(an.detail)}</span></div>`;});
    html+=`</div>`;
  }
  // dynamics
  if(a.dynamics.variable.length){
    html+=`<div style="margin-top:18px"><div class="mono" style="font-size:10.5px;letter-spacing:2px;color:var(--muted);margin-bottom:8px">SIGNAL DYNAMICS</div>`;
    a.dynamics.variable.slice(0,5).forEach(m=>{
      html+=`<div style="font-size:12.5px;color:var(--txt);padding:4px 0">${esc(m.label)} — <span style="color:${m.direction==='approaching'?'#FF9E4A':'#7CC7E8'}">${m.direction}</span> <span class="mono" style="color:var(--mid)">Δ${m.trend_db}dB over ${m.span_db}dB span</span>${m.randomized?pill('randomized — not attributable','#646E92'):''}</div>`;});
    html+=`</div>`;
  }
  el.innerHTML=html;
}
async function loadAnalysis(){
  try{const r=await fetch("/api/analysis");renderAnalysis(await r.json());}
  catch(e){document.getElementById("analysis").innerHTML=`<div class="mono" style="color:${MUTED};padding:12px 0">analysis unavailable</div>`;}
}
document.getElementById("refreshAnalysis").addEventListener("click",loadAnalysis);

document.getElementById("aiBtn").addEventListener("click",async()=>{
  const box=document.getElementById("aibox"),btn=document.getElementById("aiBtn");
  box.style.display="block";
  box.innerHTML=`<div class="mono" style="color:var(--mid);font-size:12.5px">✦ reading the surface…</div>`;
  btn.disabled=true;btn.textContent="ANALYZING…";
  try{
    const r=await fetch("/api/ai",{method:"POST"});const d=await r.json();
    if(d.error){box.innerHTML=`<div class="mono" style="font-size:12.5px;color:#FFD3BF">${esc(d.error)}</div>`;}
    else{
      const paras=d.analysis.split(/\n\n+/).map(p=>`<p style="margin:0 0 12px;font-size:13.5px;line-height:1.6;color:var(--txt)">${esc(p)}</p>`).join("");
      box.innerHTML=`<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><span class="mono" style="font-size:11px;letter-spacing:2px;color:var(--amber)">✦ AI ASSESSMENT</span><span class="mono" style="font-size:10px;color:var(--muted)">${esc(d.model||'')}</span></div>${paras}`;
    }
  }catch(e){box.innerHTML=`<div class="mono" style="color:#FFD3BF;font-size:12.5px">assessment failed: ${esc(e.message)}</div>`;}
  btn.disabled=false;btn.textContent="✦ AI ASSESSMENT";
});

// ---- RF spectrum + waterfall ----
const CAT_COLORS={broadcast:"#FF9E4A",aero:"#7CC7E8",ham:"#B48EEA",ism:"#4FD6A0",cellular:"#FF5470",pubsafety:"#F2B33D",satnav:"#5AD1C4",weather:"#7CC7E8",tv:"#FF7A45",marine:"#4F9DD6",radar:"#E86A9C",other:"#646E92"};
let RFSTATE={spectrum:[],peaks:[],noise:-90,range:null,waterfall:[],presets:{},sdr:null,active:"fm"};

function drawAnalyzer(){
  const cv=document.getElementById("analyzer");if(!cv)return;
  const dpr=window.devicePixelRatio||1, W=cv.clientWidth, H=cv.clientHeight;
  cv.width=W*dpr; cv.height=H*dpr; const g=cv.getContext("2d"); g.scale(dpr,dpr);
  g.clearRect(0,0,W,H);
  const spec=RFSTATE.spectrum; if(!spec.length){g.fillStyle=MUTED;g.font="12px 'JetBrains Mono'";g.fillText("no scan yet — hit SCAN",12,H/2);return;}
  const phi=Math.max(...spec.map(s=>s[1])), plo=Math.min(...spec.map(s=>s[1]));
  const yOf=p=>H-6-((p-plo)/((phi-plo)||1))*(H-16);
  const xOf=i=>(i/(spec.length-1))*W;
  // grid
  g.strokeStyle="rgba(46,56,96,.35)";g.lineWidth=1;
  for(let k=0;k<=4;k++){const y=6+k*(H-16)/4;g.beginPath();g.moveTo(0,y);g.lineTo(W,y);g.stroke();}
  // noise floor line
  const ny=yOf(RFSTATE.noise);g.strokeStyle="rgba(242,179,61,.4)";g.setLineDash([4,4]);g.beginPath();g.moveTo(0,ny);g.lineTo(W,ny);g.stroke();g.setLineDash([]);
  // area fill
  const grad=g.createLinearGradient(0,0,0,H);grad.addColorStop(0,"rgba(255,122,69,.5)");grad.addColorStop(.5,"rgba(40,194,180,.25)");grad.addColorStop(1,"rgba(104,78,224,.05)");
  g.beginPath();g.moveTo(0,H);spec.forEach((s,i)=>g.lineTo(xOf(i),yOf(s[1])));g.lineTo(W,H);g.closePath();g.fillStyle=grad;g.fill();
  // line
  g.beginPath();spec.forEach((s,i)=>{const x=xOf(i),y=yOf(s[1]);i?g.lineTo(x,y):g.moveTo(x,y);});g.strokeStyle="#7CE0D0";g.lineWidth=1.3;g.stroke();
  // peak markers
  const fLo=spec[0][0],fHi=spec[spec.length-1][0];
  RFSTATE.peaks.slice(0,10).forEach(pk=>{
    const x=((pk.freq_mhz-fLo)/((fHi-fLo)||1))*W, y=yOf(pk.power_db);
    const col=CAT_COLORS[pk.category]||"#646E92";
    g.fillStyle=col;g.beginPath();g.arc(x,y,3,0,7);g.fill();
    g.strokeStyle=col+"66";g.beginPath();g.moveTo(x,y);g.lineTo(x,ny);g.stroke();
  });
  // axis labels
  const ax=document.getElementById("analyzerAxis");
  if(ax)ax.innerHTML=`<span>${fLo.toFixed(1)} MHz</span><span>${((fLo+fHi)/2).toFixed(1)}</span><span>${fHi.toFixed(1)} MHz</span>`;
}

function pushWaterfall(spec){
  RFSTATE.waterfall.unshift(spec.map(s=>s[1]));
  if(RFSTATE.waterfall.length>60)RFSTATE.waterfall.pop();
  drawWaterfall();
}
function drawWaterfall(){
  const cv=document.getElementById("waterfall");if(!cv)return;
  const dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;
  cv.width=W*dpr;cv.height=H*dpr;const g=cv.getContext("2d");g.scale(dpr,dpr);
  g.clearRect(0,0,W,H);
  const rows=RFSTATE.waterfall;if(!rows.length){g.fillStyle=MUTED;g.font="12px 'JetBrains Mono'";g.fillText("waterfall builds as you scan",12,H/2);return;}
  // global min/max for consistent color mapping
  let mn=Infinity,mx=-Infinity;rows.forEach(r=>r.forEach(v=>{if(v<mn)mn=v;if(v>mx)mx=v;}));
  const rowH=Math.max(1,H/Math.min(rows.length,60));
  rows.forEach((row,ri)=>{
    const y=ri*rowH, n=row.length, cw=W/n;
    for(let i=0;i<n;i++){
      const t=(row[i]-mn)/((mx-mn)||1);
      g.fillStyle=rampColor(t);
      g.fillRect(i*cw,y,cw+.6,rowH+.6);
    }
  });
}

function renderPeaks(){
  const el=document.getElementById("rfPeaks");const pk=RFSTATE.peaks;
  if(!pk.length){el.innerHTML=`<div class="mono" style="color:${MUTED};font-size:12px">no peaks above noise floor</div>`;return;}
  let html=`<div class="mono" style="font-size:10px;letter-spacing:2px;color:var(--muted);margin-bottom:10px">IDENTIFIED SIGNALS — ${pk.length} above ${RFSTATE.noise}dB floor</div>`;
  html+=pk.slice(0,12).map(p=>{const c=CAT_COLORS[p.category]||"#646E92";
    return `<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)">
      <span style="width:8px;height:8px;border-radius:50%;background:${c};flex-shrink:0"></span>
      <span class="mono" style="width:92px;font-size:12.5px;color:var(--hi)">${p.freq_mhz} MHz</span>
      <span style="flex:1;font-size:12.5px;color:var(--txt)">${esc(p.label)}</span>
      <span class="mono" style="font-size:11px;color:${c};text-transform:uppercase;letter-spacing:1px">${p.category}</span>
      <span class="mono" style="font-size:11px;color:var(--mid);width:64px;text-align:right">${p.power_db}dB</span>
    </div>`;}).join("");
  el.innerHTML=html;
}

async function rfScan(preset){
  RFSTATE.active=preset||RFSTATE.active;
  const sim=document.getElementById("simToggle").checked;
  const btn=document.getElementById("rfScanBtn");btn.textContent="SCANNING…";btn.disabled=true;
  try{
    const body=preset?{preset,simulate:sim}:{preset:RFSTATE.active,simulate:sim};
    const r=await fetch("/api/rf/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){toast("scan: "+(d.reason||"failed"),false);}
    else{
      RFSTATE.spectrum=d.spectrum;RFSTATE.peaks=d.peaks;RFSTATE.noise=d.noise_floor_db;RFSTATE.range=d.range;
      drawAnalyzer();pushWaterfall(d.spectrum);renderPeaks();
      updatePresetChips();
      if(d.simulated)document.getElementById("sdrPill").title="simulated (no SDR)";
    }
  }catch(e){toast("scan failed: "+e.message,false);}
  btn.textContent="▚ SCAN";btn.disabled=false;
}
function updatePresetChips(){
  const box=document.getElementById("rfPresets");
  box.innerHTML=Object.entries(RFSTATE.presets).map(([k,v])=>
    `<button class="chip mono ${k===RFSTATE.active?'active':''}" data-p="${k}" style="padding:5px 10px;font-size:11px">${esc(v.title)}</button>`
  ).join("");
  box.querySelectorAll("[data-p]").forEach(n=>n.addEventListener("click",()=>rfScan(n.getAttribute("data-p"))));
}
async function initRF(){
  try{
    const s=await(await fetch("/api/rf/status")).json();
    RFSTATE.presets=s.presets;RFSTATE.sdr=s.sdr;
    const pill=document.getElementById("sdrPill");
    if(s.sdr.available){pill.textContent="SDR: "+s.sdr.tool;pill.style.color="#4FD6A0";pill.style.borderColor="#4FD6A055";document.getElementById("simToggle").checked=false;}
    else{pill.textContent="no SDR — simulating";pill.style.color=AMBER;}
    document.getElementById("modalSdr").textContent=s.sdr.note;
    updatePresetChips();
  }catch(e){}
}
document.getElementById("rfScanBtn").addEventListener("click",()=>rfScan());

// ---- settings modal ----
const modal=document.getElementById("modal");
function openModal(){modal.style.display="flex";loadKeyStatus();}
function closeModal(){modal.style.display="none";}
document.getElementById("gearBtn").addEventListener("click",openModal);
document.getElementById("modalClose").addEventListener("click",closeModal);
modal.addEventListener("click",e=>{if(e.target===modal)closeModal();});
async function loadKeyStatus(){
  try{const s=await(await fetch("/api/settings")).json();
    const k=s.keys;
    document.getElementById("keyStatus").innerHTML=k.has_anthropic
      ? `<span style="color:var(--good)">● key set</span> ${esc(k.anthropic_api_key)}${k.persisted?' · saved to disk':' · session only'}`
      : `<span style="color:var(--muted)">○ no key set — AI assessment disabled</span>`;
    document.getElementById("modalSdr").textContent=(RFSTATE.sdr&&RFSTATE.sdr.note)||"checking…";
  }catch(e){}
}
document.getElementById("keySave").addEventListener("click",async()=>{
  const key=document.getElementById("keyInput").value.trim();
  if(!key){toast("enter a key first",false);return;}
  const persist=document.getElementById("persistKey").checked;
  const r=await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({anthropic_api_key:key,persist})});
  const d=await r.json();
  document.getElementById("keyInput").value="";
  loadKeyStatus();refreshAiGate();
  toast("API key saved"+(persist?" to disk":" for this session"),true);
});
document.getElementById("keyClear").addEventListener("click",async()=>{
  await fetch("/api/settings",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({clear_anthropic:true})});
  loadKeyStatus();refreshAiGate();toast("API key cleared",true);
});
function refreshAiGate(){
  fetch("/api/ai/status").then(r=>r.json()).then(s=>{
    const b=document.getElementById("aiBtn");
    b.style.opacity=s.enabled?"1":"0.6";
    b.title=s.enabled?"":"Set an API key in ⚙ Settings to enable";
  }).catch(()=>{});
}

// ---- modes ----
let MODE="survey";
const MODE_HINTS={
  survey:"Full RF surface — everything around you, clustered and identified.",
  finder:"Locate YOUR devices. Load your allowlist; everything else is muted; walk toward the strongest.",
  sweep:"TSCM: surfaces blocklisted devices and any unlisted tracker that shouldn't be here."
};
function setMode(m){
  MODE=m;
  document.querySelectorAll(".modebtn").forEach(b=>b.classList.toggle("active",b.getAttribute("data-mode")===m));
  document.getElementById("modeHint").textContent=MODE_HINTS[m];
  document.getElementById("finderPanel").style.display=(m==="finder")?"block":"none";
  document.getElementById("sweepPanel").style.display=(m==="sweep")?"block":"none";
  if(m==="finder")loadFinder();
  if(m==="sweep")loadSweep();
}
document.getElementById("modeSel").addEventListener("click",e=>{
  const b=e.target.closest(".modebtn");if(b)setMode(b.getAttribute("data-mode"));
});

function trendBadge(t){
  if(!t)return"";
  if(t.direction==="warmer")return `<span class="warm mono" style="font-size:12px">▲ warmer +${t.delta_db}dB</span>`;
  if(t.direction==="colder")return `<span class="cold mono" style="font-size:12px">▼ colder ${t.delta_db}dB</span>`;
  return `<span class="flatt mono" style="font-size:12px">● steady</span>`;
}
function proximityWord(rssi){
  if(rssi==null)return"—";
  if(rssi>=-50)return"RIGHT HERE";
  if(rssi>=-65)return"CLOSE";
  if(rssi>=-80)return"NEARBY";
  return"FAINT";
}

async function loadFinder(){
  const body=document.getElementById("finderBody");
  try{
    const d=await(await fetch("/api/finder")).json();
    document.getElementById("finderCount").textContent=`${d.matches.length} of your devices in range · ${d.allow_count} on allowlist`;
    if(!d.allow_count && !d.matches.length){
      body.innerHTML=`<div style="text-align:center;padding:20px">
        <div style="font-size:14px;color:var(--txt)">No allowlist yet</div>
        <div style="font-size:12.5px;color:var(--mid);margin-top:6px;line-height:1.5">Load the MAC addresses of your trackers, then FINDER mutes the crowd and shows only your devices — ranked by signal so you can walk one down.</div>
        <button class="btn primary mono" style="margin-top:14px" onclick="openWL('allow')">+ ADD YOUR TRACKERS</button></div>`;
      return;
    }
    if(!d.matches.length){
      body.innerHTML=`<div style="text-align:center;padding:24px;color:var(--mid)">None of your ${d.allow_count} devices are in range right now.<br><span class="mono" style="font-size:12px">Start LIVE and move around — matches appear here the moment they're heard.</span></div>`;
      return;
    }
    // lead with the strongest as the walk-in target
    const top=d.matches[0];
    const liveR=(top.trend&&top.trend.latest!=null)?top.trend.latest:top.rssi_median;
    const col=signalColor(liveR);
    let html=`<div style="display:flex;gap:20px;align-items:center;flex-wrap:wrap;padding:12px 16px;background:var(--ink2);border-radius:12px;border:1px solid ${col}44;margin-bottom:16px">
      <div>
        <div class="mono" style="font-size:10px;letter-spacing:2px;color:var(--muted)">STRONGEST TARGET</div>
        <div class="bigrssi" style="color:${col};margin-top:4px">${liveR}<span style="font-size:16px;color:var(--mid)"> dBm</span></div>
        <div class="mono" style="font-size:13px;color:${col};margin-top:2px">${proximityWord(liveR)}</div>
      </div>
      <div style="flex:1;min-width:160px">
        <div style="font-size:15px;color:var(--hi)">${esc(top.watch_label||top.tracker_name||top.addr)}</div>
        <div class="mono" style="font-size:12px;color:var(--mid);margin-top:3px">${esc(top.addr)}</div>
        <div style="margin-top:8px">${trendBadge(top.trend)} <span class="mono" style="font-size:11px;color:var(--muted);margin-left:8px">matched by ${top.matched_by}${top.matched_by==="fingerprint"?" (rotating MAC)":""}</span></div>
        <div class="mono" style="font-size:11px;color:var(--muted);margin-top:6px">Move around and watch the number climb — no bearing, so it's warmer/colder, not a compass.</div>
      </div></div>`;
    if(d.matches.length>1){
      html+=`<div class="mono" style="font-size:10px;letter-spacing:2px;color:var(--muted);margin-bottom:8px">OTHER MATCHES</div>`;
      d.matches.slice(1).forEach(m=>{const c=signalColor(m.rssi_median);
        html+=`<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)">
          <span class="bigrssi" style="font-size:20px;color:${c};width:74px">${m.rssi_median}</span>
          <span style="flex:1"><span style="font-size:13.5px;color:var(--txt)">${esc(m.watch_label||m.tracker_name||"device")}</span>
            <span class="mono" style="display:block;font-size:11px;color:var(--muted)">${esc(m.addr)} · ${m.matched_by}</span></span>
          ${trendBadge(m.trend)}</div>`;});
    }
    body.innerHTML=html;
  }catch(e){body.innerHTML=`<div class="mono" style="color:${MUTED}">finder unavailable</div>`;}
}

async function loadSweep(){
  const body=document.getElementById("sweepBody");
  try{
    const d=await(await fetch("/api/sweep_scan")).json();
    document.getElementById("sweepCount").textContent=`${d.flags.length} flagged · ${d.block_count} on blocklist`;
    if(!d.flags.length){
      body.innerHTML=`<div style="text-align:center;padding:24px">
        <div style="font-size:15px;color:#4FD6A0">✓ Nothing flagged</div>
        <div style="font-size:12.5px;color:var(--mid);margin-top:6px;line-height:1.5">No blocklisted devices and no unlisted trackers in range. Add known-bad MACs to your blocklist, or let SPECTRA flag any tracker it fingerprints (AirTag, Tile, SmartTag) that you didn't place.</div>
        <button class="btn mono" style="margin-top:14px" onclick="openWL('block')">MANAGE BLOCKLIST</button></div>`;
      return;
    }
    body.innerHTML=d.flags.map(f=>{const c=f.flag==="block"?"#FF5470":"#F2B33D";
      return `<div style="display:flex;align-items:center;gap:14px;padding:12px 14px;background:var(--ink2);border:1px solid ${c}44;border-left:3px solid ${c};border-radius:10px;margin-bottom:10px">
        <span class="bigrssi" style="font-size:26px;color:${c};width:90px">${f.rssi_median}<span style="font-size:11px;color:var(--mid)">dBm</span></span>
        <div style="flex:1">
          <div style="font-size:14px;color:var(--hi)">${f.flag==="block"?"⛔ BLOCKLISTED":"⚠ UNLISTED TRACKER"} — ${esc(f.tracker_name||f.watch_label||"device")}</div>
          <div class="mono" style="font-size:11.5px;color:var(--mid);margin-top:3px">${esc(f.addr)} · ${proximityWord(f.rssi_median)}</div>
        </div>
        ${trendBadge(f.trend)}</div>`;}).join("");
  }catch(e){body.innerHTML=`<div class="mono" style="color:${MUTED}">sweep unavailable</div>`;}
}

// ---- watchlist modal ----
const wlModal=document.getElementById("wlModal");
let WL_TAB="allow";
const WL_DESC={
  allow:"Your own devices. In FINDER mode everything not on this list is muted, so only your trackers show. Rotating-MAC trackers (AirTags) are also caught by fingerprint.",
  block:"Known-bad devices to hunt. In SWEEP mode these flag loud, along with any unlisted tracker SPECTRA fingerprints."
};
function openWL(tab){WL_TAB=tab||WL_TAB;wlModal.style.display="flex";document.querySelectorAll(".wltab").forEach(b=>b.classList.toggle("active",b.getAttribute("data-wl")===WL_TAB));document.getElementById("wlTitle").textContent=WL_TAB==="allow"?"ALLOWLIST — MY DEVICES":"BLOCKLIST — HUNT THESE";document.getElementById("wlDesc").textContent=WL_DESC[WL_TAB];loadWL();}
function closeWL(){wlModal.style.display="none";if(MODE==="finder")loadFinder();if(MODE==="sweep")loadSweep();}
document.getElementById("wlClose").addEventListener("click",closeWL);
wlModal.addEventListener("click",e=>{if(e.target===wlModal)closeWL();});
document.querySelectorAll(".wltab").forEach(b=>b.addEventListener("click",()=>openWL(b.getAttribute("data-wl"))));
document.getElementById("finderManage").addEventListener("click",()=>openWL("allow"));
document.getElementById("sweepManage").addEventListener("click",()=>openWL("block"));
async function loadWL(){
  try{
    const d=await(await fetch("/api/watchlist")).json();
    const rows=d[WL_TAB]||[];
    const el=document.getElementById("wlList");
    if(!rows.length){el.innerHTML=`<div class="mono" style="color:${MUTED};font-size:12px;padding:8px 0">list is empty</div>`;return;}
    el.innerHTML=`<div class="mono" style="font-size:10px;letter-spacing:2px;color:var(--muted);margin-bottom:8px">${rows.length} ENTRIES</div>`+
      rows.map(r=>`<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--line)">
        <span class="mono" style="font-size:12.5px;color:var(--hi);width:150px">${esc(r.mac)}</span>
        <span style="flex:1;font-size:12.5px;color:var(--txt)">${esc(r.label||'—')}</span>
        <button class="btn mono" style="padding:4px 9px;font-size:11px" onclick="wlRemove('${esc(r.mac)}')">remove</button></div>`).join("");
  }catch(e){}
}
async function wlRemove(mac){await fetch("/api/watchlist/remove",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mac,list:WL_TAB})});loadWL();}
document.getElementById("wlImport").addEventListener("click",async()=>{
  const text=document.getElementById("wlText").value;
  if(!text.trim()){toast("paste some MACs first",false);return;}
  const d=await(await fetch("/api/watchlist/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text,list:WL_TAB})})).json();
  document.getElementById("wlText").value="";loadWL();
  toast(`imported ${d.imported} MAC${d.imported===1?'':'s'} to ${WL_TAB}list`,true);
});
document.getElementById("wlFile").addEventListener("change",e=>{
  const f=e.target.files[0];if(!f)return;const rd=new FileReader();
  rd.onload=()=>{document.getElementById("wlText").value=rd.result;toast("file loaded — review then Import",true);};
  rd.readAsText(f);e.target.value="";
});
document.getElementById("wlClear").addEventListener("click",async()=>{
  await fetch("/api/watchlist/clear",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({list:WL_TAB})});loadWL();toast("list cleared",true);
});

// tag selected emitter into a list from the detail panel (wired dynamically)
window.tagDevice=async function(mac,list){
  await fetch("/api/watchlist/add",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({mac,list,label:""})});
  toast(`added to ${list}list`,true);loadAnalysis();
};

// ---- help modal ----
const helpModal=document.getElementById("helpModal");
const HELP={
  start:`<h3>What SPECTRA is</h3><p>A passive receiver console for the wireless world around you. It listens — Wi-Fi, Bluetooth, and (with an SDR) the radio spectrum — and never transmits.</p>
    <h3>First scan in 30 seconds</h3>
    <div class="hgrid"><span class="n">1</span><span>Hit <code>START LIVE</code> (top right). SPECTRA sweeps your radios every ~20s and paints the proximity field.</span>
    <span class="n">2</span><span>Tap any point or ledger row to read full telemetry on that emitter.</span>
    <span class="n">3</span><span>Scroll to <b>Surface Intelligence</b> for device clustering, security posture, and flags.</span></div>
    <h3>Three modes</h3>
    <p><b style="color:#8AB4F8">◈ Survey</b> — the full picture of everything nearby.<br>
    <b style="color:#4FD6A0">◎ Finder</b> — locate <i>your</i> devices in a crowd (asset recovery).<br>
    <b style="color:#FF5470">◭ Sweep</b> — find devices that shouldn't be there (TSCM).</p>
    <div class="note">Nothing here needs the cloud. The AI assessment is optional and only runs if you add a key in ⚙ Settings.</div>`,
  finder:`<h3>◎ Finder — locate your own devices</h3>
    <p>Built for exactly this: you've got trackers out in the world and need to walk up to a specific one in a busy space.</p>
    <div class="hgrid">
      <span class="n">1</span><span>Switch to <b>Finder</b>, then <code>MANAGE ALLOWLIST</code>.</span>
      <span class="n">2</span><span>Paste or upload your tracker MACs — one per line, or CSV with a label: <code>AA:BB:CC:DD:EE:FF, Backpack</code>.</span>
      <span class="n">3</span><span><code>START LIVE</code> and walk. The crowd is muted; only your devices show, ranked by signal.</span>
      <span class="n">4</span><span>The <b>Strongest Target</b> card shows a big live RSSI and <span class="warm">▲ warmer</span> / <span class="cold">▼ colder</span> as you move. Walk the number up.</span></div>
    <h3>Rotating MACs (AirTags)</h3>
    <p>Some trackers rotate their MAC on a schedule, so a fixed allowlist won't hold them. Finder also matches by <b>advertisement fingerprint</b> — Find My, Tile, SmartTag — so those still surface, marked <code>fingerprint (rotating MAC)</code>. Fixed-MAC stickers match exactly; rotating ones match by type.</p>
    <div class="note">Reach is antenna, not software. Onboard radios find nearby devices; for parking-lot range add an external antenna + a BLE-capable front end (an nRF52840 sniffer or a 2.4 GHz SDR). Aiming a directional antenna is also how you get real direction — a single antenna can't measure bearing.</div>`,
  sweep:`<h3>◭ Sweep — counter-surveillance</h3>
    <p>The inverse of Finder: surface what you <i>didn't</i> put here.</p>
    <div class="hgrid">
      <span class="n">1</span><span>Switch to <b>Sweep</b>, then <code>MANAGE BLOCKLIST</code> to add known-bad MACs (optional).</span>
      <span class="n">2</span><span><code>START LIVE</code> and walk the space slowly.</span>
      <span class="n">3</span><span>Two things flag loud: anything on your blocklist (<span style="color:#FF5470">⛔</span>), and any <b>unlisted device that fingerprints as a tracker</b> (<span style="color:#F2B33D">⚠</span>) — an AirTag or Tile you didn't place.</span>
      <span class="n">4</span><span>Use the RSSI + warmer/colder to walk down anything flagged.</span></div>
    <div class="note">A hidden tracker on a rotating MAC still advertises its type. Sweep keys off that fingerprint, so it catches trackers that a MAC blocklist alone would miss.</div>`,
  rf:`<h3>RF Spectrum (needs an SDR)</h3>
    <p>Your laptop's Wi-Fi/BLE radios only demodulate two narrow bands. To scan the actual spectrum — FM, airband, ISM, ADS-B, the UHF TV band — you need a Software Defined Radio.</p>
    <div class="hgrid">
      <span class="n">1</span><span>Plug in an RTL-SDR and install <code>rtl-sdr</code> (gives you <code>rtl_power</code>). SPECTRA auto-detects it.</span>
      <span class="n">2</span><span>In the <b>RF Spectrum</b> panel, pick a preset (FM, UHF-TV, ISM-433, ADS-B…) or a custom range, then <code>SCAN</code>.</span>
      <span class="n">3</span><span>The analyzer shows power vs frequency; the waterfall builds over time; every peak is identified against the US band plan.</span></div>
    <p>No SDR yet? Leave <b>simulate</b> ticked to preview the whole thing with a realistic synthetic spectrum.</p>
    <div class="note">Coverage: RTL-SDR ≈ 24 MHz–1.7 GHz (not 2.4 GHz Wi-Fi). HackRF ≈ 1 MHz–6 GHz reaches the Wi-Fi bands. A passive sweep tells you a carrier is present and what the band is for — it isn't decoding content.</div>`,
  hardware:`<h3>Recommended field build</h3>
    <p>SPECTRA is pure Python + Flask — no compiled binary — so it runs anywhere Python does, <b>including ARM64</b> (Apple Silicon, Raspberry Pi, ClockworkPi uConsole w/ CM4).</p>
    <h3>On a uConsole / CM4</h3>
    <div class="hgrid">
      <span class="n">1</span><span>Raspberry Pi OS (64-bit). <code>git clone</code>, then <code>pip install flask bleak requests</code>.</span>
      <span class="n">2</span><span><code>python spectra_app.py</code> and open <code>127.0.0.1:8700</code> in the on-device browser.</span>
      <span class="n">3</span><span>For SDR: <code>sudo apt install rtl-sdr</code> — arm64 builds are in the repos.</span></div>
    <div class="note">Single-radio gotcha: the CM4's one Wi-Fi chip serves both your connection and the scan, so an active Wi-Fi scan briefly hiccups the link. Browse locally on the device, or use Ethernet / a second USB Wi-Fi or BLE adapter for scanning. BLE on Pi occasionally needs a <code>bluetoothctl power on</code> first.</div>
    <h3>For range (trackers in a lot)</h3>
    <p>An external antenna + a dedicated front end beats the onboard radio: an <b>nRF52840 sniffer</b> is often the best/cheapest BLE-specific option; a 2.4 GHz SDR + directional antenna also works and gives you aimable direction.</p>`,
  honest:`<h3>What SPECTRA deliberately won't fake</h3>
    <p>These aren't limitations to hide — for a practitioner they're the whole point.</p>
    <h3>No bearing</h3><p>A single passive antenna can't measure direction. SPECTRA gives you <i>warmer/colder</i> as you move, never a false compass. Real direction needs a directional antenna you aim.</p>
    <h3>Randomized MACs aren't tracked</h3><p>Modern phones and many trackers rotate their address. SPECTRA flags randomized emitters and refuses to treat them as one persistent device — it identifies them by <i>type</i> instead.</p>
    <h3>Range is an estimate</h3><p>Distance is inferred from signal strength via log-distance path loss — an order-of-magnitude bucket with error bars, not a coordinate.</p>
    <h3>Receive-only</h3><p>Everything is passive. No injection, no deauth, no association. It listens; it never transmits.</p>
    <div class="note">If a tool claims it knows more than physics allows — exact location from one antenna, tracking a device that rotates its MAC — it's selling you something.</div>`
};
function openHelp(tab){helpModal.style.display="flex";const t=tab||"start";document.querySelectorAll(".helptab").forEach(b=>b.classList.toggle("active",b.getAttribute("data-h")===t));const body=document.getElementById("helpBody");body.className="helpBody";body.innerHTML=HELP[t];}
document.getElementById("helpBtn").addEventListener("click",()=>openHelp("start"));
document.getElementById("helpClose").addEventListener("click",()=>helpModal.style.display="none");
helpModal.addEventListener("click",e=>{if(e.target===helpModal)helpModal.style.display="none";});
document.getElementById("helpTabs").addEventListener("click",e=>{const b=e.target.closest(".helptab");if(b)openHelp(b.getAttribute("data-h"));});

// refresh finder/sweep when a live sweep lands
connect=function(){
  const es=new EventSource("/api/stream");
  es.onmessage=ev=>{let d;try{d=JSON.parse(ev.data);}catch(e){return;}
    if(d.surface)STATE.surface=d.surface;
    if(typeof d.running==="boolean")STATE.running=d.running;
    if(d.sweep!=null)STATE.sweep=d.sweep;
    if(d.state&&d.state.sweep_count!=null)STATE.sweep=d.state.sweep_count;
    if(d.type==="error")toast("radio: "+d.message,false);
    if(d.type==="sweep")toast(`sweep ${d.sweep} — ${d.observations} observations`,true);
    renderAll();
    if(d.type==="sweep"||d.type==="snapshot"){loadAnalysis();if(MODE==="finder")loadFinder();if(MODE==="sweep")loadSweep();}
  };
  es.onerror=()=>{};
};

setMode("survey");
initRF();
refreshAiGate();
renderAll();
loadAnalysis();
connect();
window.addEventListener("resize",()=>{drawAnalyzer();drawWaterfall();});
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    p = argparse.ArgumentParser(description="SPECTRA live RF surface server.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8700)
    p.add_argument("--interval", type=int, default=20, help="seconds between live sweeps")
    p.add_argument("--ble-seconds", type=float, default=6.0)
    p.add_argument("--demo", action="store_true",
                   help="seed a synthetic field into a separate demo DB (no radios needed)")
    p.add_argument("--db", metavar="PATH", help="use a specific database file")
    p.add_argument("--retain", type=float, metavar="HOURS", default=None,
                   help="delete observations older than N hours after each sweep "
                        "(default: keep everything; use 'purge' to clear manually)")
    p.add_argument("--allow-host", metavar="HOSTS", default="",
                   help="comma-separated extra Host values to accept (needed with --host)")
    p.add_argument("--window", type=float, metavar="HOURS", default=None,
                   help=f"surface reports cover the last N hours "
                        f"(default {spectra.DEFAULT_WINDOW_HOURS:g}; 0 = all history)")
    p.add_argument("--autostart", action="store_true", help="begin live sweeping on launch")
    args = p.parse_args()

    collector.interval = args.interval
    collector.ble_seconds = args.ble_seconds

    if args.db:
        spectra.use_db(args.db)

    collector.window_hours = args.window
    collector.retain_hours = args.retain
    win = spectra.DEFAULT_WINDOW_HOURS if args.window is None else args.window
    print(
        f"surface window: last {win:g}h"
        if win > 0
        else "surface window: ALL history (stale emitters will be reported)"
    )
    if args.retain:
        print(f"retention: observations older than {args.retain:g}h are deleted each sweep")

    if args.demo:
        # Synthetic data goes in its own database. Seeding it into the live
        # surface would leave fake emitters in every later report.
        if not args.db:
            spectra.use_db(spectra.DEMO_DB)
        n = seed_demo()
        print(f"seeded {n} synthetic observations -> {spectra.DB_PATH}")
        print("demo mode: your live surface is untouched")
    else:
        print(f"live surface -> {spectra.DB_PATH}")

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        # The request guard only answers to loopback Host headers. Binding
        # elsewhere is therefore an explicit choice the operator has to make
        # twice: once to bind, once to widen the guard.
        extra = {h.strip() for h in (args.allow_host or "").split(",") if h.strip()}
        if extra:
            ALLOWED_HOSTS.update(extra)
            print(
                f"\n  WARNING: binding to {args.host} and accepting Host headers for "
                f"{', '.join(sorted(extra))}.\n"
                "  There is still NO authentication — anyone who can reach this port can\n"
                "  read your surface, edit your watchlists, and spend your API key.\n"
                "  Only do this behind a VPN or a reverse proxy that authenticates.\n"
            )
        else:
            print(
                f"\n  WARNING: bound to {args.host}, but the request guard still only\n"
                "  answers to 127.0.0.1 / localhost, so remote clients will get 403.\n"
                "  Add --allow-host <name-or-ip> to widen it. There is no authentication:\n"
                "  anyone who can reach this port can read your surface, edit your\n"
                "  watchlists, and spend your API key.\n"
            )

    if args.autostart:
        collector.start()

    print(f"SPECTRA console -> http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()
