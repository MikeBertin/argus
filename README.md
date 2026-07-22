# 🔷 Project ARGUS — Packet-Capture Detection Engine

> *The hundred eyes that never sleep — every flow inspected, nothing slips past.*

## What This Is
ARGUS is a pcap detection-rule engine. You point it at a packet capture and it
returns a ranked list of findings — known exploits, exfiltration patterns, and
suspicious behaviour — each tagged with severity, confidence, and a MITRE ATT&CK
technique. Detections are pluggable Python rule classes, auto-discovered from a
`rules/` directory, so the engine grows by adding rules, not by editing the core.

## Goal & Why It Matters
A genuinely useful, portfolio-grade network-forensics tool built on a clean,
extensible architecture — the value is the engine design (flow assembly + rule
plugin model), not the rule count. Supports the SPECTRE / OSCP track by turning
raw captures into "look here first" triage.

## Why ARGUS
Argus Panoptes — the hundred-eyed giant of Greek myth who never fully slept and
watched everything at once. The right metaphor for a many-eyed engine inspecting
every packet and flow.

## Status
**15 detection rules**, TLS JA3/JA4/JA4S fingerprinting, four batch surfaces
(CLI/JSON · self-contained HTML report · web server · browser-upload app) and a
**live IDS mode** (windowed detection streaming to console/JSON-lines/syslog/webhook/
live dashboard). 70 tests, GitHub Actions CI green.

## Architecture (summary)
```
pcap → [Ingest] → [Normalize] → [Flow Assembly] → [Rule Engine] → [Findings] → [Reporters]
        pyshark    packet→event   5-tuple sessions  inspect/finalize  severity +    CLI / JSON
                                                     per Rule plugin   ATT&CK tag
```
- **Two-pass model**: rules see each packet (`inspect_packet`) and then render
  flow-level verdicts (`finalize`) — required for behavioural detections.
- **Ingest**: `pyshark` (wraps `tshark` — `brew install wireshark` required).
- **Rules**: Python subclasses of a single `Rule` base, auto-discovered.

## Quickstart
```bash
# one-time setup
brew install wireshark                 # provides tshark
python3.13 -m venv .venv               # pyshark 0.6 needs Python 3.13 (not 3.14)
.venv/bin/pip install -r requirements.txt
.venv/bin/python fixtures/generate.py  # craft the synthetic attack pcaps

# run it
.venv/bin/python -m argus.cli fixtures/pcaps/zerologon.pcap     # → CRITICAL zerologon
.venv/bin/python -m argus.cli --json <pcap>                     # machine-readable
.venv/bin/python -m argus.cli --html report.html <pcap>         # self-contained dashboard
.venv/bin/python -m argus.cli --serve <pcap>                    # serve the dashboard on localhost:8000
.venv/bin/python -m argus.cli --upload                          # browser upload app: drop a pcap, get the report
sudo .venv/bin/python -m argus.cli --interface en0 --bpf "tcp"  # LIVE monitor an interface (IDS mode)
.venv/bin/python -m argus.cli --list-rules
.venv/bin/python -m argus.cli --update-ja3                      # refresh JA3 blocklist from abuse.ch
.venv/bin/python -m pytest                                      # 61 tests
```
Exit code is non-zero when any HIGH/CRITICAL finding is present (CI-friendly).

### HTML report
`--html PATH` writes a **single self-contained file** (all CSS/JS/SVG inline, no CDN —
correct for an offline forensics artifact you can attach to a ticket). It includes a
severity donut, a MITRE ATT&CK matrix grouped by tactic, a finding timeline, and a
sortable/filterable findings table with click-to-expand evidence and packet frame
numbers. Rendering is split into `build_report_model()` (data) and `render_html()`
(view) in [`argus/htmlreport.py`](argus/htmlreport.py) — the same seam reused by the
`--serve` and `--upload` web modes below.

## Rules
| Rule | Fires on | ATT&CK | Severity | Positive fixture |
|------|----------|--------|----------|------------------|
| `zerologon` | Netlogon `NetrServerAuthenticate3` burst, all-zero client credential | T1210 | CRITICAL | `zerologon.pcap` (real) |
| `dns_tunnel` | High-entropy / long / high-volume subdomains per parent domain | T1071.004 | HIGH | generated |
| `icmp_exfil` | Repeated oversized ICMP echo payloads to one host | T1048.003 | HIGH | generated |
| `cleartext_creds` | HTTP Basic auth or login-form password without TLS | T1040 | MEDIUM | generated |
| `beaconing` | Many low-jitter connections to one dst:port | T1071 | MEDIUM | generated |
| `port_scan` | One src probing many ports/hosts with unestablished SYNs (vertical + horizontal) | T1046 | MEDIUM | generated |
| `arp_spoof` | One IP address claimed by 2+ MAC addresses (cache poisoning) | T1557.002 | HIGH | generated |
| `bruteforce` | Many established login connections to one auth service (SMB/RDP/SSH/…) | T1110 | HIGH | generated |
| `tls_fingerprint` | TLS **JA3 + JA4** (Client Hello) and **JA4S** (Server Hello) matched against a known-bad blocklist (+ fingerprint enrichment for all TLS) | T1573 | HIGH / INFO | generated |
| `llmnr_spoof` | One responder answering LLMNR/NBT-NS queries for many distinct names (Responder) | T1557.001 | HIGH | generated |
| `rogue_dhcp` | Conflicting gateway/DNS offered via DHCP (rogue server redirecting traffic) | T1557 | HIGH | generated |
| `kerberoasting` | One client requesting many distinct SPN service tickets with a weak (RC4/DES) encryption type — offline-crackable harvesting | T1558.003 | HIGH | generated |
| `smb_lateral` | One host writing an executable to another's admin disk share (ADMIN$/C$) — PsExec-style service-binary drop | T1021.002 | HIGH | generated |
| `dns_zone_transfer` | A DNS AXFR/IXFR query — bulk dump of an entire zone (a complete internal-namespace map); HIGH when the transfer returns records | T1590.002 | MEDIUM / HIGH | generated |
| `tls_cert_anomaly` | A TLS server cert that is self-signed, expired/not-yet-valid, or carries a placeholder subject; HIGH for the disposable-attacker-cert combination | T1587.003 | MEDIUM / HIGH | generated |

### TLS fingerprinting (JA3 + JA4 client, JA4S server)
`tls_fingerprint` computes both the [JA3](https://github.com/salesforce/ja3) and the
newer [JA4](https://github.com/FoxIO-LLC/ja4) (FoxIO) fingerprint of every TLS Client
Hello, **and JA4S of every Server Hello** (GREASE-aware). It flags **HIGH** when any
matches a known-bad blocklist, and records **INFO** enrichment carrying the
fingerprints for every other TLS client/server so analysts can pivot on the client or
server stack (e.g. identify a C2 server by its JA4S across IPs). JA4 is validated
byte-for-byte against tshark's native `tls.handshake.ja4`, and JA4S against FoxIO's
reference implementation values — both in the test suite.

The blocklist holds JA3 MD5s and/or JA4 strings — an embedded seed (no fabricated
malware attributions) plus an optional live feed cached locally:
```bash
argus --update-ja3                       # pull + cache abuse.ch SSLBL JA3 feed
argus --update-ja3 --ja3-feed-url URL    # use a different feed
```
The cache merges over the seed at load time, so detection still works offline afterwards.

### Live monitoring (IDS mode)
`--interface` sniffs an interface and streams findings in real time instead of reading a
file — ARGUS becomes a continuous monitor:
```bash
sudo argus --interface en0 --bpf "tcp port 445" --window 120 --tick 5 --jsonl /tmp/argus.ndjson
```
Rules aggregate over a **sliding time window** (per-rule timestamped events, evicted each
tick) and findings are **de-duplicated** so a scan isn't re-alerted every tick. Live
capture needs packet-capture privileges (`sudo` / BPF on macOS, `cap_net_raw` on Linux).
The same rules run in batch and live — batch (`analyze`) simply never evicts.

**Output sinks** (composable; console is always on): `--jsonl PATH` (JSON-lines for SIEM
ingestion), `--syslog [ADDRESS]` (local socket or `host:port` remote UDP; severity → syslog
priority), and `--webhook URL` (POSTs each finding as JSON with a Slack-style `text` field;
a flaky endpoint warns once and never stops the monitor). Use `--min-severity MEDIUM` to
keep INFO enrichment off syslog/webhook.
```bash
sudo argus --interface en0 --syslog --webhook https://hooks.example/argus --min-severity HIGH
```
`--dashboard` additionally serves a **live-updating web dashboard** (localhost) that polls
for new findings every 2s — severity tallies and a growing findings table, same theme as
the static report:
```bash
sudo argus --interface en0 --dashboard --port 8000   # → http://127.0.0.1:8000/
```

### Web-server mode
`--serve` analyses the pcap and serves the report over HTTP instead of writing a file —
`GET /` returns the interactive dashboard, `GET /report.json` the model:
```bash
argus --serve capture.pcap --port 8000   # → http://127.0.0.1:8000/
```
Standard-library `http.server` (no new dependency), bound to **localhost only** (findings
are sensitive). Reuses the same `build_report_model()` / `render_html()` as `--html`.

`--upload` serves a **browser upload app** — drop a `.pcap`/`.pcapng` in the page and get
the interactive report back, no terminal needed. Bound to localhost, single-threaded
(pyshark's tshark subprocess is main-thread-only), with a 64 MB upload cap; the uploaded
file is analysed in a temp file and deleted immediately after.

**False-positive guards** (harness asserts zero findings): `http.cap` (web browsing),
`dns+icmp.pcapng` (normal PTR lookups + pings), `nb6-startup.pcap` (NetBIOS startup).
Only `zerologon.pcap` is genuinely malicious; the synthetic positives for the other
rules are crafted by `fixtures/generate.py` (scapy).

## Key Files
| File / dir | Purpose |
|------------|---------|
| `argus/engine.py` | Drives ingest → flow assembly → rules → ranked findings |
| `argus/rules/` | Auto-discovered detection plugins (one file per rule) |
| `argus/context.py` | Flow table + windowed event store (`WindowStore`) |
| `argus/live.py` | Live monitor loop + output sinks |
| `argus/server.py`, `argus/htmlreport.py` | Web modes + HTML report/dashboard/upload rendering |
| `fixtures/generate.py` | Synthetic attack pcaps (scapy) |
| `tests/` | pytest suite (positives + false-positive guards) |

## Notes
- **Dependency**: `pyshark` requires `tshark` (`brew install wireshark`).
- **Python 3.13** venv required — pyshark 0.6 is incompatible with 3.14 (removed asyncio APIs).
- Real test captures (`fixtures/pcaps/*.pcap`) are public sample captures (TryHackMe /
  Wireshark samples); only `zerologon.pcap` is malicious. Synthetic attack fixtures are
  generated by `fixtures/generate.py` (scapy) and gitignored.

> *Any quotes used in this project must be real, sourced attributions. No invented quotes.*
