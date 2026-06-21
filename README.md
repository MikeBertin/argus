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
.venv/bin/python -m argus.cli --list-rules
.venv/bin/python -m pytest                                      # 26 tests
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
