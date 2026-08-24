# SPECTRA — Passive RF Surface Console

Passive Wi-Fi / BLE / (with an SDR) spectrum console. Receive-only. Runs anywhere
Python does, including ARM64 (Apple Silicon, Raspberry Pi, ClockworkPi uConsole + CM4).

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Receive only](https://img.shields.io/badge/RF-receive--only-lightgrey)

> **Status: pre-release.** Read [Known limitations](#known-limitations) before you
> trust any output — several will change what you conclude from a scan, especially
> in Sweep mode. There is **no authentication**: keep it bound to `127.0.0.1`.

## What this is, and what it is not

SPECTRA tells you what is broadcasting around you and how confident it is about
each claim. The design constraint is honesty over impressiveness — where the
physics does not support a conclusion, it says so rather than producing a
plausible number.

**It does:** passively receive Wi-Fi and BLE advertisements, cluster them into
probable devices, estimate range with explicit error bars, flag security posture,
and optionally sweep wider spectrum with an RTL-SDR.

**It does not, and will not:** transmit, associate, inject frames, deauthenticate,
capture handshakes, crack anything, or give you a compass bearing to a device. A
single omnidirectional antenna cannot produce direction, so SPECTRA gives you
warmer/colder instead of pretending otherwise. Randomized MAC addresses are
flagged as untrackable rather than correlated across sessions.

Pull requests adding transmit or attack capability will not be merged. See
[SECURITY.md](SECURITY.md).

## Files
- `spectra.py` — collection engine (Wi-Fi/BLE scan, storage, OUI, k-anonymity)
- `spectra_analysis.py` — device clustering, security posture, channel/anomaly analysis
- `spectra_rf.py` — SDR spectrum scan + US band-plan ID + BLE tracker fingerprinting
- `spectra_watch.py` — allow/block watchlists, finder & sweep logic
- `spectra_app.py` — Flask server + the whole web console UI

## Quick start
```bash
pip install -r requirements.txt
python spectra_app.py --demo          # synthetic field, no radios, separate DB
python spectra_app.py                 # live — uses your radios
```
Open http://127.0.0.1:8700 and hit **START LIVE**. Tap **?** for the in-app guide.

Demo data goes to `~/.spectra/demo.db` and live captures to `~/.spectra/surface.db`,
so previewing the UI never contaminates a real survey. Each `--demo` launch resets
the demo database.

## Three modes (top bar)
- **Survey** — full RF surface, clustered and identified.
- **Finder** — locate YOUR devices. Load an allowlist of tracker MACs; the crowd
  is muted; your devices rank by signal with a big walk-in RSSI readout. Rotating
  MACs (AirTags) are caught by advertisement fingerprint, not just MAC.
- **Sweep** — TSCM. Blocklisted devices and any unlisted tracker flag loud.

## Watchlists
Finder → MANAGE ALLOWLIST, or Sweep → MANAGE BLOCKLIST. Paste or upload MACs:
```
AA:BB:CC:DD:EE:FF, Backpack sticker
aabbccdd0011, Wallet
11-22-33-44-55-66 ; Car tag
```
Colon / dash / bare-hex all accepted; label optional.

## Windows, retention, and stored data

Surface reports cover the **last hour by default**. Emitters inside the window
that have not been heard in the last three minutes are marked STALE rather than
reported as present. Both are configurable:

```bash
python spectra_app.py --window 0.25          # 15-minute surface
python spectra_app.py --window 0             # all history (forensics)
python spectra_app.py --retain 24            # prune >24h after each sweep
SPECTRA_WINDOW_HOURS=6 SPECTRA_PRESENT_SECONDS=300 python spectra_app.py
```

Windowing controls what a report *shows*; retention controls what the database
*keeps*. Clear it manually with:

```bash
python spectra.py report --window 0.5        # last 30 minutes
python spectra.py purge                      # wipe the live surface (prompts)
python spectra.py purge --older-than 24      # drop anything older than 24h
python spectra.py purge --yes                # skip the prompt
python spectra.py --db ~/.spectra/demo.db purge --yes
```

The `--db` flag goes *before* the subcommand. `SPECTRA_DB` and `SPECTRA_HOME`
environment variables work too.

## SDR (spectrum beyond Wi-Fi/BLE)
Plug in an RTL-SDR + `sudo apt install rtl-sdr`. SPECTRA auto-detects `rtl_power`.
Presets: FM, airband, weather, VHF/UHF TV, ISM 315/433/915, ADS-B, GPS, wideband.
No SDR? Leave **simulate** ticked to preview.

**HackRF is detected but not yet wired**, so `rtl_power` is preferred when both
are present — see limitation 5.

## uConsole / CM4 notes
- 64-bit Pi OS; `rtl-sdr` is in the repos (arm64).
- The CM4's single Wi-Fi radio serves both your connection and the scan — browse
  locally on the device, or use Ethernet / a 2nd USB Wi-Fi or BLE adapter for scanning.
- BLE on Pi sometimes needs `bluetoothctl power on` first.
- For parking-lot range: external antenna + nRF52840 sniffer (best for BLE) or a
  2.4 GHz SDR + directional antenna (also gives aimable direction).

## Known limitations

Fixed since the first testing build: the recency window, dynamics windowing,
tracker over-flagging, device clustering, HackRF selection, stale channel and
security values, CSRF and DNS rebinding, and the silent macOS scan failure.
What follows is what is still true.

**1. No authentication.** The console has no login. A request guard now rejects
cross-site state changes and non-loopback `Host` headers, which stops a drive-by
from another tab, but that is not access control. Binding elsewhere takes two
deliberate flags (`--host` and `--allow-host`) and should only happen behind a
VPN or an authenticating reverse proxy.

**2. Device count is still an estimate.** Clustering no longer chains across a
corridor and no longer merges radios advertising different named networks, but
inferring physical enclosures from OUI and signal remains inference. `bssid_count`
is measured; `device_estimate` is a guess reported as medium confidence.

**3. Sweep will still produce false positives.** Fingerprints now require word
boundaries and no longer treat a vendor name as a tag, and Fast Pair accessories
are reported as accessories rather than trackers. But a fingerprint match still
means "the advertisement looks like this family," not "someone planted this."

**4. Reports scan the window on every request.** Queries are now bounded by time
and hit the `ts` index, so cost tracks the window rather than all history. There
is still no cached current-state table, so a very wide `--window 0` on a large
database will be slow.

**5. HackRF is detected but unimplemented.** `rtl_power` is now preferred so
owning a HackRF no longer breaks scanning, but its wider coverage is unused.

**6. Retention is opt-in.** `--retain HOURS` prunes after each sweep, and `purge`
clears manually, but the default still keeps every observation indefinitely.

**7. Linux signal conversion is approximate.** `nmcli`'s signal percentage is
converted to dBm with a linear formula NetworkManager does not guarantee.

## Honest limits (by design)
No bearing from a single antenna (warmer/colder, not a compass). Randomized MACs
flagged, not tracked. Range is a log-distance estimate with error bars. Receive-only:
no monitor mode, no injection, no deauth, no handshake capture, no association.

## Scope and data handling
Run this against your own environment. Passive reception is generally lawful, but
sustained collection and geolocation of third-party devices is a different activity
with a different legal posture. The database records every device in range,
including other people's. Retention defaults to unlimited — set `--retain` to a
window you can justify, and `purge` when you are done.

## Contributing

Issues and pull requests are welcome. Two things to know before you open one:

- The honesty constraints in "What this is, and what it is not" are the point of
  the project, not an oversight. Changes that make an estimate look more certain
  than the underlying signal supports will be declined.
- Known limitations are documented rather than hidden. If you are about to report
  one, check that section first — and if you have a fix for it, that is exactly
  the contribution worth making.

Security issues go through the process in [SECURITY.md](SECURITY.md), not the
public issue tracker.

## License

MIT — see [LICENSE](LICENSE).

## Optional AI
⚙ Settings → paste an Anthropic API key (session, or save to disk chmod 600).
Then the AI assessment reads the computed surface and prioritizes findings. The model
receives a derived summary, never raw observations. The default model is set by
`SPECTRA_AI_MODEL`.
