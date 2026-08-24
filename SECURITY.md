# Security Policy

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability**
button under the Security tab, rather than opening a public issue.

Include what you did, what happened, and the version or commit. A proof of concept
helps but is not required. Expect an acknowledgement within a few days; SPECTRA is
maintained alongside other work, so a fix timeline comes after triage rather than
with it.

## What is in scope

SPECTRA runs as a local web console. The interesting attack surface is:

- Anything that lets a **remote or cross-origin party** reach the API. The request
  guard rejects non-loopback `Host` headers and cross-site state changes; a bypass
  of either is in scope.
- **Injection into the console UI** from data an attacker controls. SSIDs, BLE
  device names, and advertisement payloads are all attacker-supplied — a nearby
  radio can broadcast whatever it likes. Anything that escapes escaping and
  executes in the page is in scope.
- **Disclosure of the stored API key** beyond the intended masked form.
- **Path or command injection** through SDR parameters, watchlist import, or
  export paths.

## What is already known and is not a finding

These are documented in the README under Known limitations. Reports restating them
will be closed as known:

- **There is no authentication.** The request guard stops a drive-by from another
  browser tab. It is not access control, and SPECTRA is not safe to expose. Binding
  to a non-loopback interface requires two deliberate flags precisely because it is
  a bad idea without an authenticating proxy in front.
- **The Werkzeug development server** is what ships. It is appropriate for a local
  single-user tool and is not hardened for exposure.
- **Observations are retained indefinitely by default.** That is a configuration
  choice (`--retain`, `purge`), not a vulnerability.
- **The device estimate and tracker fingerprints are heuristics** and produce both
  false positives and false negatives by design.

## Scope of the tool itself

SPECTRA is receive-only. It does not transmit, associate, inject, deauthenticate,
or capture handshakes, and pull requests adding those capabilities will not be
merged. If you find a path by which it transmits, that is a bug and very much in
scope.

## Responsible use

This tool observes third-party devices as an unavoidable consequence of listening
to a shared medium. Passive reception is broadly lawful in most jurisdictions, but
sustained collection, correlation, or geolocation of other people's devices is a
different activity with a different legal posture, and that posture varies by
country and by state. You are responsible for the deployment you choose.
