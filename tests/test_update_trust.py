"""Tests for the iam:UpdateAssumeRolePolicy trust-rewrite hop."""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import ADMIN, find_paths
from iam_escalate.model import Account, Principal
from iam_escalate.hops import update_trust_edges

FIXTURE = Path(__file__).parent.parent / "fixtures" / "update_trust_account.json"


def test_trust_rewrite_reaches_admin_despite_locked_trust():
    # locked-role does NOT trust tina, but she can rewrite its trust and assume it.
    paths = find_paths(load_account_from_file(str(FIXTURE)))
    tina = next(p for p in paths if p.source == "trust-editor-tina")
    assert tina.nodes == ["trust-editor-tina", "locked-role", ADMIN]
    assert "update_trust_policy" in tina.hop_techniques[0]


def test_no_edge_without_assume_permission():
    # nate can edit trust but can't call sts:AssumeRole, so no path.
    sources = {p.source for p in find_paths(load_account_from_file(str(FIXTURE)))}
    assert "no-assume-nate" not in sources


def test_update_trust_edge_requires_both_permissions():
    role = Principal(name="r", arn="arn:aws:iam::1:role/r", ptype="role")
    both = Principal(name="both", arn="arn:aws:iam::1:user/both", ptype="user",
                     allowed_actions={"iam:UpdateAssumeRolePolicy", "sts:AssumeRole"})
    only_edit = Principal(name="edit", arn="arn:aws:iam::1:user/edit", ptype="user",
                          allowed_actions={"iam:UpdateAssumeRolePolicy"})
    edges = update_trust_edges(Account(principals=[role, both, only_edit]))
    assert ("both", "r", "update_trust_policy") in edges
    assert not any(src == "edit" for src, _, _ in edges)
