"""Command line interface for pypromptcage."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from ._core import VERSION, inspect_output, inspect_prompt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pypromptcage", description="Inspect LLM prompt input or output for prompt-security risks.")
    parser.add_argument("file", nargs="?", help="read text from this file instead of standard input")
    parser.add_argument("--output", action="store_true", help="scan model output rather than prompt input")
    parser.add_argument("--json", action="store_true", help="print the full report as JSON")
    parser.add_argument("--version", action="store_true", help="print the package version and exit")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        sys.stdout.write(VERSION + "\n")
        return 0
    try:
        if args.file:
            with open(args.file, "r", encoding="utf-8") as handle:
                text = handle.read()
        else:
            text = sys.stdin.read()
        report = inspect_output(text) if args.output else inspect_prompt(text)
    except Exception as error:  # bounded CLI error boundary
        sys.stderr.write(str(error) + "\n")
        return 64

    if args.json:
        sys.stdout.write(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write("{} risk={} findings={}\n".format(report.action, report.risk_score, report.finding_count))
        for finding in report.findings[:10]:
            sys.stdout.write("{} {} {}\n".format(finding.id, finding.severity, finding.description))
    if report.action == "block":
        return 2
    if report.action == "warn":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
