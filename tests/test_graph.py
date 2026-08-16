"""Tests for the escalation graph and path search (M4 4a).

With only direct rules feeding the graph, every path to admin is a single
hop, so results mirror the direct findings. These tests lock that in
before hop-based rules extend paths.
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import ADMIN, find_paths
from iam_escalate.model import Account, Principal

SAMPLE = Path(__file__).parent.parent / "fixtures" / "sample_account.json"


def test_direct_escalator_has_path_to_admin():
    sources = {p.source for p in find_paths(load_account_from_file(str(SAMPLE)))}
    assert "dev-intern" in sources


def test_safe_user_has_no_path():
    sources = {p.source for p in find_paths(load_account_from_file(str(SAMPLE)))}
    assert "readonly-bob" not in sources


def test_direct_path_is_a_single_hop():
    paths = find_paths(load_account_from_file(str(SAMPLE)))
    dev = next(p for p in paths if p.source == "dev-intern")
    assert dev.nodes == ["dev-intern", ADMIN]  # exactly one hop to admin


def test_multiple_techniques_aggregate_on_one_edge():
    account = Account(
        principals=[Principal(name="super", arn="arn:aws:iam::123:user/super",
                              ptype="user", allowed_actions={"iam:*"})]
    )
    super_path = next(p for p in find_paths(account) if p.source == "super")
    # iam:* enables several direct techniques; they ride the single hop.
    assert len(super_path.hop_techniques[0]) >= 2
