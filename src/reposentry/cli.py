from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .render import render_json, render_markdown
from .scanner import scan_repository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Statically inspect a local repository without running its code.")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Scan a local repository path.")
    scan.add_argument("path", type=Path, help="Local repository directory")
    scan.add_argument("--format", choices=("markdown", "json"), default="markdown")
    scan.add_argument("--output", type=argparse.FileType("w"), default=sys.stdout)
    scan.add_argument("--online", action="store_true", help="Query public PyPI and npm metadata; packages are never downloaded.")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = build_parser().parse_args(argv)
    try:
        report = scan_repository(args.path, online=args.online)
    except ValueError as error:
        logging.error("Scan failed: %s", error)
        return 2
    args.output.write(render_json(report) if args.format == "json" else render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
