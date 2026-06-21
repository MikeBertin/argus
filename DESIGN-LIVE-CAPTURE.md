# ARGUS — Live Interface Capture (design / not yet implemented)

> Status: **PLANNED, not built.** This doc is the implementation plan agreed 2026-06-21.
> ARGUS today is a batch forensics tool (reads a `.pcap`). Live mode turns it into a
> continuous monitor (IDS) that sniffs an interface and emits findings in real time.

## 1. Motivation
Read packets off a live interface (`en0`/`eth0`) as they flow, instead of from a
saved file — detect attacks *while they happen* rather than post-incident.

## 2. The core challenge — `finalize()` assumes a finite capture
The current engine (`engine.py`) is two-pass:
1. per packet → `ctx.observe(pkt)` + every `rule.inspect_packet(pkt, ctx)`
2. **once at the end** → every `rule.finalize(ctx)` → sort → `AnalysisResult`

A file ends; a live stream does not. Most rules do their real work in `finalize()`
over *unbounded-growth* state (`ctx.scratch`, the flow table). Naively running this
live would (a) never emit aggregate findings (no "end"), and (b) leak memory and
permanently latch thresholds (e.g. `port_scan`'s distinct-port count only grows).

**So live mode is not "swap `FileCapture` → `LiveCapture`". The real work is moving
aggregating rules from "finalize once" to "evaluate over a sliding time window with
state eviction", plus de-duplicating repeated findings.**

## 3. Approach (recommended): windowed-finalize + eviction + dedup
Keep the existing `inspect_packet`/`finalize` rule interface; add a live runner:

```
live loop:
  for (pkt, now) in source:                 # source = LiveCapture, or replay in tests
     ctx.observe(pkt)
     for r in rules: emit(r.inspect_packet(pkt, ctx))   # immediate findings now
     if now - last_tick >= TICK:            # e.g. every 5s
        ctx.evict(older_than = window)      # drop aged events from flows + scratch
        for r in rules: candidate += r.finalize(ctx)     # windowed verdicts
        emit(dedup(candidate))              # suppress repeats within a cooldown
        last_tick = now
```

Why this shape: minimal rule churn (interface unchanged), and `finalize()` over a
*windowed* `ctx` is exactly today's logic. The new machinery is in the engine/context,
not in 11 rules.

**Alternative considered — incremental emission** (rules emit the moment a threshold
is crossed inside `inspect_packet`): lower latency, but requires rewriting every
aggregating rule and per-rule "already-fired" bookkeeping. Heavier; deferred.

## 4. Required changes
| Area | Change |
|------|--------|
| `ingest.py` | add `read_live(interface, bpf_filter=None)` → `pyshark.LiveCapture(...).sniff_continuously()` → `normalize()` (reused as-is). |
| `context.py` | store a timestamp on every scratch event; add `evict(window)` to prune flows, `packet_times`, and per-rule scratch older than the window. **This is the main new infra.** |
| rules (aggregating) | store accumulator entries as `(ts, …)` so eviction can drop them; thresholds then reflect "within the window". Stateless rules (below) need no change. |
| `engine.py` | add `Engine.monitor(source, tick, window)` live loop (the pseudocode above) separate from `analyze()`. |
| new `livefindings.py` | finding de-duplication: key = `(rule_id, src, dst, salient-evidence)`; suppress within a cooldown so a 60s scan isn't re-alerted every tick. |
| `report.py` | streaming sink: print each finding as it fires (human line + JSON-lines `--jsonl`); no final table. |
| `cli.py` | `--interface <iface>` (mutually exclusive with `pcap`), `--bpf <filter>`, `--window`, `--tick`. |

## 5. Per-rule impact
- **Work live ~as-is (per-packet / immediate):** `cleartext_creds` (already emits in
  `inspect_packet`), `tls_fingerprint` blocklist hit (emit on first sighting).
- **Need windowed state + eviction:** `zerologon`, `dns_tunnel`, `icmp_exfil`,
  `beaconing`, `port_scan`, `bruteforce`, `arp_spoof`, `llmnr_spoof`, `rogue_dhcp`,
  `tls_fingerprint` enrichment.
- **Per-rule window sizes differ** and must be configurable: `port_scan` seconds;
  `beaconing` minutes; `rogue_dhcp`/`arp_spoof` tens of seconds.

## 6. Testability (decide up front)
Live sniffing can't run in CI (no interface, needs root). **Decouple the clock and the
packet source**: `Engine.monitor(source, now_fn)` takes an iterator of `(pkt, ts)` and
an injectable clock. Tests **replay a fixture pcap through the live/windowed path with
simulated timestamps** and assert: findings fire, dedup suppresses repeats, eviction
drops stale state and lets a threshold re-arm. Deterministic, no interface, CI-safe.
`LiveCapture` is then a thin real-interface adapter around the same loop.

## 7. Operational concerns
- **Privileges:** `LiveCapture` needs root/BPF. macOS: access to `/dev/bpf*`; Linux:
  `setcap cap_net_raw,cap_net_admin=eip` on dumpcap, or sudo. Detect & message clearly.
- **Performance:** pyshark→tshark subprocess has a real-time throughput ceiling.
  Mitigate with a **BPF pre-filter** (`--bpf`) to cut volume at the kernel. Adequate for
  lab/host monitoring (project scope); high-rate links would need a different capture lib.
- **Memory:** bounded only by eviction — window + cap on tracked entities per rule.
- **Shutdown:** Ctrl-C → flush a final windowed pass + summary.
- **Optional:** feed the deferred web-server mode for a live-updating dashboard
  (reuses `build_report_model`/`render_html`).

## 8. Phased plan
1. **Live ingest + immediate rules** — `read_live`, `monitor()` loop running only the
   per-packet/immediate detections. Proves the pipeline end-to-end on a real interface.
2. **Windowing infra** — `ctx.evict()`, the periodic tick, finding dedup; convert
   aggregating rules to timestamped/prunable scratch. The bulk of the work.
3. **Ops & output** — `--interface`/`--bpf`/`--window`/`--tick`, JSON-lines sink,
   privilege handling, graceful shutdown. Replay-based tests throughout.
4. **(Optional)** live HTML dashboard / web-server integration; metrics.

## 9. Open decisions (resolve before building)
- Default window + per-rule overrides (config schema).
- Output sink(s): stdout / JSON-lines / syslog / file / webhook.
- Windowed-finalize (recommended) vs incremental-emission.
- Whether to bundle the live dashboard now or keep CLI-only first.

## 10. Rough effort
Phase 1 small; **Phase 2 is the substantial piece** (eviction + windowing across 10
rules + dedup + replay tests). Phases 3–4 moderate. Treat as a multi-session feature,
not a single rule add.
