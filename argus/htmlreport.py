"""Self-contained HTML report surface for ARGUS.

Two pure functions, deliberately decoupled so a future ``argus/server.py`` can
reuse both without change:

    build_report_model(result, source) -> dict     # data only, JSON-serialisable
    render_html(model)                 -> str       # one offline .html file

The rendered file embeds all CSS, JS and chart SVG inline — no CDN, no external
asset fetches — which is the correct property for an offline forensics artifact.
The only outbound URLs are attack.mitre.org anchor hrefs (not asset loads).
"""

from __future__ import annotations

import html
import json
import math
from datetime import datetime, timezone

from argus.attack import lookup, technique_url
from argus.engine import AnalysisResult
from argus.models import Severity

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Single source of truth for severity colours (shared by CSS + SVG charts).
SEV_COLORS = {
    "CRITICAL": "#ff3b5c",
    "HIGH": "#ff7849",
    "MEDIUM": "#ffd23f",
    "LOW": "#4ea8de",
    "INFO": "#8a8f98",
}
CLEAN_COLOR = "#2ea043"


# --------------------------------------------------------------------------- #
# Model
# --------------------------------------------------------------------------- #
def build_report_model(result: AnalysisResult, source: str) -> dict:
    sev_counts = {name: 0 for name in SEV_ORDER}
    for f in result.findings:
        sev_counts[f.severity.name] += 1

    agg: dict[str, dict] = {}
    for f in result.findings:
        for tid in f.mitre:
            a = agg.setdefault(tid, {"count": 0, "max_sev": Severity.INFO})
            a["count"] += 1
            a["max_sev"] = max(a["max_sev"], f.severity)
    attack = []
    for tid, a in agg.items():
        meta = lookup(tid)
        attack.append(
            {
                "id": tid,
                "name": meta.name,
                "tactic": meta.tactic,
                "url": technique_url(tid),
                "count": a["count"],
                "max_severity": a["max_sev"].name,
            }
        )
    attack.sort(key=lambda x: (-Severity[x["max_severity"]], x["id"]))

    duration = 0.0
    if result.start_ts and result.end_ts:
        duration = max(0.0, result.end_ts - result.start_ts)

    return {
        "source": source,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "packets": result.packet_count,
        "flows": result.flow_count,
        "rules_run": result.rules_run,
        "capture_start": result.start_ts,
        "capture_end": result.end_ts,
        "duration_s": round(duration, 2),
        "severity_counts": sev_counts,
        "attack": attack,
        "findings": [f.to_dict() for f in result.findings],
    }


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #
def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _fmt_time(ts: float | None) -> str:
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 90:
        return f"{seconds:.1f}s"
    if s < 5400:
        return f"{s // 60}m {s % 60}s"
    if s < 172800:
        return f"{s // 3600}h {(s % 3600) // 60}m"
    return f"{s // 86400}d"


# --------------------------------------------------------------------------- #
# Charts (hand-rolled inline SVG)
# --------------------------------------------------------------------------- #
def _donut_svg(sev_counts: dict[str, int]) -> str:
    total = sum(sev_counts.values())
    r, cx, cy, sw = 60, 80, 80, 22
    circ = 2 * math.pi * r

    if total == 0:
        ring = (
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{CLEAN_COLOR}" stroke-width="{sw}"/>'
        )
        label = f'<text x="{cx}" y="{cy+4}" class="donut-num" fill="{CLEAN_COLOR}">0</text>'
        return f'<svg viewBox="0 0 160 160" width="160" height="160">{ring}{label}</svg>'

    segments = []
    offset = 0.0
    for name in SEV_ORDER:
        count = sev_counts.get(name, 0)
        if not count:
            continue
        seg = count / total * circ
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" '
            f'stroke="{SEV_COLORS[name]}" stroke-width="{sw}" '
            f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" '
            f'stroke-dashoffset="{-offset:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"><title>{name}: {count}</title></circle>'
        )
        offset += seg
    num = f'<text x="{cx}" y="{cy}" class="donut-num">{total}</text>'
    sub = f'<text x="{cx}" y="{cy+18}" class="donut-sub">findings</text>'
    return (
        f'<svg viewBox="0 0 160 160" width="160" height="160">'
        f'{"".join(segments)}{num}{sub}</svg>'
    )


def _timeline_svg(findings: list[dict], start: float | None, end: float | None) -> str:
    W, padL, padR, top, laneH = 760, 120, 24, 24, 30
    present = [s for s in SEV_ORDER if any(f["severity"] == s for f in findings)]
    has_wide = any(not f.get("ts") for f in findings)
    rows = present + (["NO TIMESTAMP"] if has_wide else [])
    if not rows:
        return '<svg viewBox="0 0 760 80" width="100%"><text x="20" y="44" class="tl-axis">No findings to plot.</text></svg>'

    plotW = W - padL - padR
    H = top + len(rows) * laneH + 36
    span = (end - start) if (start and end and end > start) else 0
    row_y = {name: top + i * laneH + laneH / 2 for i, name in enumerate(rows)}

    parts = [f'<svg viewBox="0 0 {W} {H}" width="100%" height="{H}">']

    # lane labels + guide lines
    for name in rows:
        y = row_y[name]
        color = SEV_COLORS.get(name, "#6e7681")
        parts.append(
            f'<text x="{padL-12}" y="{y+4}" class="tl-lane" text-anchor="end" '
            f'fill="{color}">{name}</text>'
        )
        parts.append(
            f'<line x1="{padL}" y1="{y}" x2="{W-padR}" y2="{y}" class="tl-guide"/>'
        )

    # markers
    wide_idx = 0
    wide_total = max(1, sum(1 for f in findings if not f.get("ts")))
    for f in findings:
        sev = f["severity"]
        ts = f.get("ts")
        if ts and span:
            x = padL + (ts - start) / span * plotW
            y = row_y[sev]
        elif ts:
            x = padL + plotW / 2
            y = row_y[sev]
        else:
            x = padL + (wide_idx + 0.5) / wide_total * plotW
            y = row_y["NO TIMESTAMP"]
            wide_idx += 1
        title = _esc(f["title"])
        parts.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="{SEV_COLORS[sev]}" '
            f'stroke="#0e1116" stroke-width="1.5"><title>{title}</title></circle>'
        )

    # axis
    axis_y = H - 18
    parts.append(f'<line x1="{padL}" y1="{axis_y}" x2="{W-padR}" y2="{axis_y}" class="tl-axisline"/>')
    parts.append(f'<text x="{padL}" y="{axis_y+14}" class="tl-axis">{_fmt_time(start)}</text>')
    parts.append(
        f'<text x="{W-padR}" y="{axis_y+14}" class="tl-axis" text-anchor="end">{_fmt_time(end)}</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def _attack_matrix_html(attack: list[dict]) -> str:
    if not attack:
        return '<p class="muted">No ATT&amp;CK techniques triggered.</p>'
    by_tactic: dict[str, list[dict]] = {}
    for t in attack:
        by_tactic.setdefault(t["tactic"], []).append(t)

    cols = []
    for tactic, techs in by_tactic.items():
        cells = []
        for t in techs:
            color = SEV_COLORS[t["max_severity"]]
            cells.append(
                f'<a class="attack-cell" href="{_esc(t["url"])}" target="_blank" '
                f'rel="noopener" style="border-left:4px solid {color}">'
                f'<span class="attack-id">{_esc(t["id"])}</span>'
                f'<span class="attack-name">{_esc(t["name"])}</span>'
                f'<span class="attack-count">{t["count"]}×</span></a>'
            )
        cols.append(
            f'<div class="attack-col"><div class="attack-tactic">{_esc(tactic)}</div>'
            f'{"".join(cells)}</div>'
        )
    return f'<div class="attack-matrix">{"".join(cols)}</div>'


def _summary_cards(model: dict) -> str:
    cards = [
        f'<div class="card"><div class="card-num">{model["packets"]}</div><div class="card-lbl">packets</div></div>',
        f'<div class="card"><div class="card-num">{model["flows"]}</div><div class="card-lbl">flows</div></div>',
        f'<div class="card"><div class="card-num">{model["rules_run"]}</div><div class="card-lbl">rules</div></div>',
    ]
    for name in SEV_ORDER:
        count = model["severity_counts"][name]
        if count == 0 and name in ("INFO", "LOW"):
            continue
        color = SEV_COLORS[name]
        cards.append(
            f'<div class="card sev" style="border-top:3px solid {color}">'
            f'<div class="card-num" style="color:{color}">{count}</div>'
            f'<div class="card-lbl">{name.lower()}</div></div>'
        )
    return f'<div class="cards">{"".join(cards)}</div>'


def _findings_table(findings: list[dict]) -> str:
    if not findings:
        return (
            '<div class="clean-banner">✓ No findings — this capture looks clean.</div>'
        )
    rows = []
    for i, f in enumerate(findings):
        sev = f["severity"]
        color = SEV_COLORS[sev]
        attack_links = " ".join(
            f'<a href="{_esc(technique_url(t))}" target="_blank" rel="noopener">{_esc(t)}</a>'
            for t in f["mitre"]
        )
        endpoints = "—"
        if f.get("src") or f.get("dst"):
            endpoints = f'{_esc(f.get("src") or "?")} → {_esc(f.get("dst") or "?")}'
        evidence = "".join(
            f'<div class="ev"><span class="ev-k">{_esc(k)}</span>'
            f'<span class="ev-v">{_esc(v)}</span></div>'
            for k, v in f.get("evidence", {}).items()
            if v is not None
        )
        frames = ", ".join(str(p) for p in f.get("packets", []))
        rows.append(
            f'<tr class="frow" data-sev="{Severity[sev]}" data-rule="{_esc(f["rule_id"])}" '
            f'data-conf="{f["confidence"]}" onclick="argusToggle({i})">'
            f'<td><span class="pill" style="background:{color}">{sev}</span></td>'
            f'<td class="mono">{_esc(f["rule_id"])}</td>'
            f'<td class="num">{f["confidence"]:.2f}</td>'
            f'<td class="mono small">{endpoints}</td>'
            f'<td class="small">{attack_links}</td>'
            f'<td class="num small">{_fmt_time(f.get("ts"))}</td>'
            f'<td>{_esc(f["title"])}</td></tr>'
            f'<tr class="detail" id="detail-{i}"><td colspan="7">'
            f'<div class="detail-box">{evidence}'
            f'<div class="ev"><span class="ev-k">frames</span>'
            f'<span class="ev-v mono">{frames or "—"}</span></div></div></td></tr>'
        )
    head = (
        '<tr><th data-key="sev" onclick="argusSort(\'sev\')">Severity ▾</th>'
        '<th data-key="rule" onclick="argusSort(\'rule\')">Rule</th>'
        '<th data-key="conf" onclick="argusSort(\'conf\')">Conf</th>'
        '<th>Src → Dst</th><th>ATT&amp;CK</th><th>Time</th><th>Finding</th></tr>'
    )
    return f'<table id="findings"><thead>{head}</thead><tbody>{"".join(rows)}</tbody></table>'


def _filter_bar(sev_counts: dict[str, int]) -> str:
    btns = ['<button class="fbtn active" onclick="argusFilter(\'ALL\',this)">All</button>']
    for name in SEV_ORDER:
        if sev_counts[name]:
            color = SEV_COLORS[name]
            btns.append(
                f'<button class="fbtn" style="border-color:{color};color:{color}" '
                f'onclick="argusFilter(\'{name}\',this)">{name} {sev_counts[name]}</button>'
            )
    return f'<div class="filters">{"".join(btns)}</div>'


# --------------------------------------------------------------------------- #
# Render
# --------------------------------------------------------------------------- #
def _css() -> str:
    sev_vars = "".join(f"--sev-{k.lower()}:{v};" for k, v in SEV_COLORS.items())
    return f"""
:root{{{sev_vars}--bg:#0e1116;--panel:#161b22;--line:#21262d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}}
.wrap{{max-width:1080px;margin:0 auto;padding:28px}}
header{{display:flex;align-items:center;gap:16px;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:22px}}
.eye{{flex:none}}
h1{{margin:0;font-size:24px;letter-spacing:3px}}
.sub{{color:var(--muted);font-size:13px;margin-top:2px}}
.sub code{{color:var(--accent)}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:20px}}
.panel h2{{margin:0 0 14px;font-size:13px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted)}}
.grid{{display:grid;grid-template-columns:200px 1fr;gap:24px;align-items:center}}
.cards{{display:flex;flex-wrap:wrap;gap:12px}}
.card{{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:12px 18px;min-width:84px;text-align:center}}
.card-num{{font-size:26px;font-weight:600}}
.card-lbl{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px}}
.donut-num{{font-size:30px;font-weight:700;fill:var(--text);text-anchor:middle;dominant-baseline:middle}}
.donut-sub{{font-size:11px;fill:var(--muted);text-anchor:middle;text-transform:uppercase;letter-spacing:1px}}
.legend{{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px}}
.legend span{{font-size:12px;color:var(--muted)}}
.dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:middle}}
.attack-matrix{{display:flex;gap:14px;flex-wrap:wrap}}
.attack-col{{flex:1;min-width:180px}}
.attack-tactic{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--line)}}
.attack-cell{{display:block;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;margin-bottom:8px;text-decoration:none;color:var(--text)}}
.attack-cell:hover{{border-color:var(--accent)}}
.attack-id{{font-family:ui-monospace,monospace;font-weight:600;font-size:13px}}
.attack-name{{display:block;color:var(--muted);font-size:12px}}
.attack-count{{float:right;color:var(--muted);font-size:12px}}
.tl-lane{{font-size:11px;font-weight:600;letter-spacing:.5px}}
.tl-guide{{stroke:var(--line);stroke-width:1;stroke-dasharray:2 4}}
.tl-axisline{{stroke:var(--line);stroke-width:1}}
.tl-axis{{font-size:11px;fill:var(--muted)}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}}
.fbtn{{background:transparent;border:1px solid var(--line);color:var(--text);border-radius:20px;padding:5px 14px;cursor:pointer;font-size:12px}}
.fbtn.active{{background:var(--text);color:var(--bg);border-color:var(--text)}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);cursor:pointer;user-select:none}}
.frow{{cursor:pointer}}
.frow:hover{{background:#1b222b}}
.pill{{display:inline-block;padding:2px 9px;border-radius:12px;color:#0e1116;font-weight:700;font-size:11px}}
.mono{{font-family:ui-monospace,SFMono-Regular,monospace}}
.small{{font-size:12px}}
.num{{text-align:right;font-variant-numeric:tabular-nums}}
td a{{color:var(--accent);text-decoration:none}}
.detail{{display:none}}
.detail.open{{display:table-row}}
.detail-box{{background:var(--bg);border-radius:6px;padding:12px;display:flex;flex-wrap:wrap;gap:8px 24px}}
.ev{{font-size:12px}}
.ev-k{{color:var(--muted);margin-right:8px;text-transform:uppercase;letter-spacing:.5px}}
.ev-v{{color:var(--text)}}
.clean-banner{{background:rgba(46,160,67,.12);border:1px solid {CLEAN_COLOR};color:{CLEAN_COLOR};border-radius:8px;padding:18px;text-align:center;font-size:15px}}
.muted{{color:var(--muted)}}
footer{{color:var(--muted);font-size:12px;text-align:center;margin-top:24px}}
"""


def _legend(sev_counts: dict[str, int]) -> str:
    items = []
    for name in SEV_ORDER:
        if sev_counts[name]:
            items.append(
                f'<span><span class="dot" style="background:{SEV_COLORS[name]}"></span>'
                f'{name} {sev_counts[name]}</span>'
            )
    return f'<div class="legend">{"".join(items)}</div>' if items else ""


_EYE_SVG = (
    '<svg class="eye" width="40" height="40" viewBox="0 0 40 40">'
    '<ellipse cx="20" cy="20" rx="18" ry="11" fill="none" stroke="#58a6ff" stroke-width="2"/>'
    '<circle cx="20" cy="20" r="6" fill="#58a6ff"/>'
    '<circle cx="20" cy="20" r="2.5" fill="#0e1116"/></svg>'
)

_JS = """
function argusToggle(i){var d=document.getElementById('detail-'+i);if(d)d.classList.toggle('open');}
function argusFilter(sev,btn){
  document.querySelectorAll('.fbtn').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  document.querySelectorAll('.frow').forEach(function(r){
    var show = (sev==='ALL') || (r.children[0].textContent.trim()===sev);
    r.style.display = show?'':'none';
  });
  document.querySelectorAll('.detail').forEach(function(d){d.classList.remove('open')});
}
var argusAsc={};
function argusSort(key){
  var tb=document.querySelector('#findings tbody');
  var rows=Array.prototype.slice.call(tb.querySelectorAll('.frow'));
  argusAsc[key]=!argusAsc[key];var dir=argusAsc[key]?1:-1;
  rows.sort(function(a,b){
    if(key==='sev')  return dir*(+a.dataset.sev  - +b.dataset.sev);
    if(key==='conf') return dir*(+a.dataset.conf - +b.dataset.conf);
    return dir*a.dataset.rule.localeCompare(b.dataset.rule);
  });
  rows.forEach(function(r){
    tb.appendChild(r);
    var det=r.nextElementSibling;
    if(det&&det.classList.contains('detail'))tb.appendChild(det);
  });
}
"""


def render_html(model: dict) -> str:
    sev_counts = model["severity_counts"]
    data_json = json.dumps(model)
    cap_window = "—"
    if model["capture_start"] and model["capture_end"]:
        cap_window = (
            f'{_fmt_time(model["capture_start"])}–{_fmt_time(model["capture_end"])} UTC '
            f'· {_fmt_duration(model["duration_s"])}'
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARGUS report — {_esc(model["source"])}</title>
<style>{_css()}</style></head>
<body><div class="wrap">
<header>{_EYE_SVG}<div>
<h1>ARGUS</h1>
<div class="sub">Detection report · <code>{_esc(model["source"])}</code></div>
<div class="sub">Generated {_esc(model["generated_at"])} · capture {cap_window}</div>
</div></header>

<div class="panel"><h2>Overview</h2>
<div class="grid">
<div style="text-align:center">{_donut_svg(sev_counts)}{_legend(sev_counts)}</div>
<div>{_summary_cards(model)}</div>
</div></div>

<div class="panel"><h2>MITRE ATT&amp;CK coverage</h2>{_attack_matrix_html(model["attack"])}</div>

<div class="panel"><h2>Finding timeline</h2>
{_timeline_svg(model["findings"], model["capture_start"], model["capture_end"])}</div>

<div class="panel"><h2>Findings ({len(model["findings"])})</h2>
{_filter_bar(sev_counts)}
{_findings_table(model["findings"])}</div>

<footer>ARGUS · the hundred eyes that never sleep</footer>
</div>
<script type="application/json" id="argus-data">{data_json}</script>
<script>{_JS}</script>
</body></html>"""
