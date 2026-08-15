"""Command-line entry point.

    iam-escalate analyze fixtures/sample_account.json --report out.html
    iam-escalate collect --profile myaccount --out account.json

`analyze` uses only the standard library, so it runs with nothing
installed. `collect` needs boto3 (the .[aws] extra).
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .collector import collect_from_aws, load_account_from_file
from .engine import analyze as run_analysis
from .report import to_html, to_markdown


def _cmd_analyze(args: argparse.Namespace) -> int:
    account = load_account_from_file(args.input)
    findings = run_analysis(account)

    if args.report and args.report.endswith(".html"):
        text = to_html(findings)
    else:
        text = to_markdown(findings)

    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Wrote {len(findings)} finding(s) to {args.report}")
    else:
        print(text)

    # Non-zero exit if anything was found — handy for CI/pipeline use.
    return 1 if findings else 0


def _cmd_collect(args: argparse.Namespace) -> int:
    collect_from_aws(args.profile, args.out)
    print(f"Wrote account data to {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="iam-escalate", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="find escalation paths in a saved IAM dump")
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
