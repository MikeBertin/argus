"""ARGUS command-line entry point."""

from __future__ import annotations

import argparse
import sys

from argus.engine import Engine
from argus.loader import discover_rules
from argus.models import Severity
from argus.report import render_cli, render_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="argus",
        description="Packet-capture detection-rule engine.",
    )
    p.add_argument("pcap", nargs="?", help="path to a .pcap/.pcapng capture")
    p.add_argument("--json", action="store_true", help="emit findings as JSON")
    p.add_argument(
        "--html",
        metavar="PATH",
        help="write a self-contained HTML report to PATH",
    )
    p.add_argument(
        "--min-severity",
        choices=[s.name for s in Severity],
        default="INFO",
        help="suppress findings below this severity",
    )
    p.add_argument(
        "--rule",
        action="append",
        dest="rules",
        metavar="ID",
        help="only run the named rule(s); repeatable",
    )
    p.add_argument(
        "--list-rules",
        action="store_true",
        help="list available detection rules and exit",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    all_rules = discover_rules()

    if args.list_rules:
        for r in all_rules:
            print(f"{r.id:18} {r.severity.name:9} {', '.join(r.mitre):10} {r.name}")
        return 0

    if not args.pcap:
        build_parser().error("a pcap path is required (or use --list-rules)")

    rules = all_rules
    if args.rules:
        wanted = set(args.rules)
        rules = [r for r in all_rules if r.id in wanted]
        if not rules:
            print(f"No rules matched {sorted(wanted)}", file=sys.stderr)
            return 2

    result = Engine(rules=rules).analyze(args.pcap)

    min_sev = Severity[args.min_severity]
    result.findings = [f for f in result.findings if f.severity >= min_sev]

    if args.html:
        from argus.htmlreport import build_report_model, render_html

        model = build_report_model(result, args.pcap)
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(render_html(model))
        print(f"wrote HTML report → {args.html}")

    if args.json:
        print(render_json(result, args.pcap))
    elif not args.html:
        render_cli(result, args.pcap)

    # Exit non-zero when something high/critical was found (CI-friendly).
    return 1 if any(f.severity >= Severity.HIGH for f in result.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
