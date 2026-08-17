"""Command-line entry point.

    iam-escalate analyze fixtures/sample_account.json --report out.html
    iam-escalate collect --profile myaccount --out account.json

`analyze` finds escalation *paths* to admin (direct and multi-hop) and
renders them. `collect` needs boto3 (the .[aws] extra).
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .collector import collect_from_aws, load_account_from_file
from .engine import run_direct_rules
from .graph import find_paths
from .report import paths_to_html, paths_to_markdown


def _cmd_analyze(args: argparse.Namespace) -> int:
    account = load_account_from_file(args.input)
    paths = find_paths(account)
    direct = run_direct_rules(account)  # supplies exploit/remediation for terminal hops

    if args.report and args.report.endswith(".html"):
        text = paths_to_html(paths, direct, account)
    else:
        text = paths_to_markdown(paths, direct, account)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Wrote {len(paths)} escalation path(s) to {args.report}")
    else:
        print(text)

    # Non-zero exit if any path to admin exists — handy for CI/pipeline use.
    return 1 if paths else 0


def _cmd_collect(args: argparse.Namespace) -> int:
    collect_from_aws(args.profile, args.out)
    print(f"Wrote account data to {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam-escalate", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="find escalation paths to admin in a saved IAM dump")
    a.add_argument("input", help="path to a GetAccountAuthorizationDetails-shaped JSON file")
    a.add_argument("--report", help="write to this file (.html for HTML, else Markdown)")
    a.set_defaults(func=_cmd_analyze)

    c = sub.add_parser("collect", help="pull live IAM data via boto3 (needs the .[aws] extra)")
    c.add_argument("--profile", help="AWS named profile to use")
    c.add_argument("--out", default="account.json", help="where to write the dump")
    c.set_defaults(func=_cmd_collect)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
