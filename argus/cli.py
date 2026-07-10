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
        "--serve",
        action="store_true",
        help="analyse the pcap and serve the report over HTTP (localhost)",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8000,
        help="port for --serve (default 8000)",
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
    p.add_argument(
        "--update-ja3",
        action="store_true",
        help="refresh the JA3 blocklist from the feed and exit",
    )
    p.add_argument(
        "--ja3-feed-url",
        metavar="URL",
        help="override the JA3 feed URL used by --update-ja3",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.update_ja3:
        from argus.fingerprint_blocklist import DEFAULT_FEED_URL, update_from_feed

        url = args.ja3_feed_url or DEFAULT_FEED_URL
        try:
            count = update_from_feed(url)
        except Exception as exc:  # network/parse failure — report clearly
            print(f"JA3 feed update failed ({url}): {exc}", file=sys.stderr)
            return 2
        print(f"JA3 blocklist updated: {count} fingerprints cached from {url}")
        return 0

    all_rules = discover_rules()

    if args.list_rules:
        for r in all_rules:
            print(f"{r.id:18} {r.severity.name:9} {', '.join(r.mitre):10} {r.name}")
        return 0

    if not args.pcap:
        build_parser().error("a pcap path is required (or use --list-rules)")

    if args.serve:
        from argus.server import serve

        serve(args.pcap, port=args.port)
        return 0

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
