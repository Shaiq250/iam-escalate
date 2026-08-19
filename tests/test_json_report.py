"""Tests for the JSON report format."""

import json
from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.engine import run_direct_rules
from iam_escalate.graph import find_paths
from iam_escalate.report import paths_to_json

CHAIN = Path(__file__).parent.parent / "fixtures" / "assume_role_chain_account.json"
CAVEATS = Path(__file__).parent.parent / "fixtures" / "caveats_account.json"


def _json(fixture):
    account = load_account_from_file(str(fixture))
    return json.loads(paths_to_json(find_paths(account), run_direct_rules(account), account))


def test_json_is_valid_and_has_paths():
    data = _json(CHAIN)
    assert isinstance(data["paths"], list) and data["paths"]


def test_json_path_has_source_and_hops():
    low = next(p for p in _json(CHAIN)["paths"] if p["source"] == "low-larry")
    assert low["hops"][0]["from"] == "low-larry"
    assert low["hops"][-1]["to"] == "admin"
    assert "assume_role" in low["hops"][0]["techniques"]


def test_json_terminal_hop_has_exploit_and_fix():
    low = next(p for p in _json(CHAIN)["paths"] if p["source"] == "low-larry")
    assert "exploit" in low["hops"][-1] and "fix" in low["hops"][-1]


def test_json_reports_not_fully_evaluated():
    data = _json(CAVEATS)
    names = {row["principal"] for row in data["not_fully_evaluated"]}
    assert "opaque-olga" in names
