"""Tests for the path-centric report (M5 5a)."""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.engine import run_direct_rules
from iam_escalate.graph import find_paths
from iam_escalate.model import Account
from iam_escalate.report import paths_to_markdown

CHAIN = Path(__file__).parent.parent / "fixtures" / "assume_role_chain_account.json"


def _md(fixture):
    account = load_account_from_file(str(fixture))
    return paths_to_markdown(find_paths(account), run_direct_rules(account))


def test_report_shows_the_multi_hop_chain():
    md = _md(CHAIN)
    assert "low-larry" in md and "admin-role" in md
    assert "2 hops" in md


def test_report_names_the_hop_technique():
    assert "Assume role (sts:AssumeRole)" in _md(CHAIN)


def test_report_shows_terminal_exploit_and_fix():
    md = _md(CHAIN)
    assert "attach-user-policy" in md  # exploit command for the admin-reaching step
    assert "Fix:" in md


def test_empty_report_when_no_paths():
    md = paths_to_markdown(find_paths(Account(principals=[])), [])
    assert "No escalation paths to admin found" in md
