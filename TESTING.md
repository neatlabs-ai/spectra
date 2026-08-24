# SPECTRA — test round

Thanks for taking this. It is pre-release: the known problems are listed in
README → Known limitations, and re-reporting those is not useful. What *is*
useful is anything not on that list, plus the four runs below.

## Setup

```bash
git clone <repo> && cd spectra
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python spectra_app.py --demo
```

Open http://127.0.0.1:8700. Demo mode needs no radios and writes to a separate
database, so you can poke at every screen before touching a live capture.

Please note your OS and version, Python version, `pip freeze` output, and what
radios/adapters you are using. Most of what will go wrong is environmental.

## Run 1 — demo mode, no hardware (15 min)

Click through all three modes, the SDR panel with **simulate** ticked, the
watchlist import box, the settings modal, and the in-app help. Looking for: dead
buttons, layout breakage at your window size, anything that reads as wrong or
confusing. Screenshots welcome.

Try pasting deliberately malformed input into the watchlist box — junk lines,
half-MACs, very long labels, unicode. It should ignore what it cannot parse and
not corrupt the list.

## Run 2 — live, your own space (30 min)

```bash
python spectra.py purge --yes
python spectra_app.py
```

Hit START LIVE. Then, before anything else, sanity-check the count: does the
device estimate match what you know is actually in your home or office? Where it
is wrong, tell me which direction and by how much — that is the most valuable
signal in this whole round.

Also worth checking: does your own router show the right vendor, security, and
channel? Does BLE find anything at all? On Linux you may need
`bluetoothctl power on` first; on macOS you will need to grant Location Services
or Wi-Fi scanning returns nothing.

## Run 3 — Finder, with a real tracker (20 min)

Put a tracker you own (AirTag, Tile, SmartTag, a pair of earbuds) on the
allowlist, switch to Finder, and try to walk it down from across a room or floor.
Looking for: does the RSSI readout actually track your movement, does the
warmer/colder badge feel right, and does a rotating-MAC tracker get caught by
fingerprint rather than dropping off the list.

Say honestly whether you could have found the thing with this. If the answer is
"not really," that is the finding.

## Run 4 — long run, dense environment (1 hr, the important one)

Somewhere with a lot of RF — an apartment building, a coffee shop, an office.
Start clean, let it sweep for an hour, then capture:

```bash
python spectra.py export --format json --out spectra_1hr.json
```

Send me that file plus a note on what the UI showed at the end. The recency window, dynamics windowing and clustering were just rewritten, and
this run is what validates them. Specifically:

- Does the device estimate stay stable over the hour, or does it creep?
- Does anything stationary get labelled as approaching or receding?
- Do your neighbours' access points stay separate, or collapse together?
- How many emitters end up STALE versus present, and does that match reality?

Try `--window 0.25` and `--window 0` on the same database and compare. The
difference between those two is the whole point of the change.

If you run Sweep there, false flags should now be rare — please count them, and
send me the `ble_hint` text of anything that flags wrongly. That string is what
the fingerprint matched on and is exactly what I need to tighten it further.

## Reporting

Open an issue per finding, or one document, whichever suits you. What helps:

- what you did, what you expected, what happened
- OS, Python version, hardware
- the console output and any browser JS errors (F12 → Console)
- the exported JSON when the finding is about analysis rather than UI

## Two things to please avoid

**Do not run with `--host 0.0.0.0`** on any shared network. There is no
authentication yet.

**Do not use Sweep to draw a conclusion about anyone.** The false-positive rate is
high enough right now that a flag means "the fingerprint matched," nothing more.
The point of this round is to measure that rate, not to act on it.
