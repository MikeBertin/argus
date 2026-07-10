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

## Milestones
| # | Milestone | Target |
|---|-----------|--------|
| 1 | Core pipeline + plugin loader + flow assembly, one rule end-to-end on `zerologon.pcap` | TBD |
| 2 | Five starter rules + MITRE tags + ranked CLI report | TBD |
| 3 | Test harness over the 4 fixture pcaps (incl. false-positive guard) | TBD |

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
sudo .venv/bin/python -m argus.cli --interface en0 --bpf "tcp"  # LIVE monitor an interface (IDS mode)
.venv/bin/python -m argus.cli --list-rules
.venv/bin/python -m argus.cli --update-ja3                      # refresh JA3 blocklist from abuse.ch
.venv/bin/python -m pytest                                      # 50 tests
```
Exit code is non-zero when any HIGH/CRITICAL finding is present (CI-friendly).

### HTML report
`--html PATH` writes a **single self-contained file** (all CSS/JS/SVG inline, no CDN —
correct for an offline forensics artifact you can attach to a ticket). It includes a
severity donut, a MITRE ATT&CK matrix grouped by tactic, a finding timeline, and a
sortable/filterable findings table with click-to-expand evidence and packet frame
numbers. Rendering is split into `build_report_model()` (data) and `render_html()`
(view) in [`argus/htmlreport.py`](argus/htmlreport.py), leaving a clean seam for a
future web-server mode.

## Rules (v0.1)
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

### Web-server mode
`--serve` analyses the pcap and serves the report over HTTP instead of writing a file —
`GET /` returns the interactive dashboard, `GET /report.json` the model:
```bash
argus --serve capture.pcap --port 8000   # → http://127.0.0.1:8000/
```
Standard-library `http.server` (no new dependency), bound to **localhost only** (findings
are sensitive). Reuses the same `build_report_model()` / `render_html()` as `--html`.

**False-positive guards** (harness asserts zero findings): `http.cap` (web browsing),
`dns+icmp.pcapng` (normal PTR lookups + pings), `nb6-startup.pcap` (NetBIOS startup).
Only `zerologon.pcap` is genuinely malicious; the synthetic positives for the other
rules are crafted by `fixtures/generate.py` (scapy).

## Key Files
| File | Purpose |
|------|---------|
| `README.md` | This file |
| `STATUS.md` | Current state and next action |
| `log.md` | Decisions, progress, session notes |

## Notes
- **Dependency**: `pyshark` requires `tshark` (`brew install wireshark`).
- Test pcaps are copied in from `dev/THM/` as fixtures; originals stay in the archive.
- Source of the captures: TryHackMe / public sample captures.

> *Any quotes used in this project must be real, sourced attributions. No invented quotes.*
