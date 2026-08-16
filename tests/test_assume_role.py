"""Tests for AssumeRole hop edges and multi-hop path finding (M4 4b)."""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import ADMIN, find_paths
from iam_escalate.model import Account, Principal

FIXTURE = Path(__file__).parent.parent / "fixtures" / "assume_role_chain_account.json"


def _paths():
    return find_paths(load_account_from_file(str(FIXTURE)))


def test_multi_hop_path_is_found():
    larry = next((p for p in _paths() if p.source == "low-larry"), None)
    assert larry is not None
    assert larry.nodes == ["low-larry", "admin-role", ADMIN]  # two hops


def test_hop_is_assume_role_then_direct_escalation():
    larry = next(p for p in _paths() if p.source == "low-larry")
    assert larry.hop_techniques[0] == ["assume_role"]
    assert "attach_user_policy" in larry.hop_techniques[1]


def test_untrusted_caller_has_no_path():
    # ned holds sts:AssumeRole but the role's trust policy doesn't name him
    # (and it doesn't trust account-root), so no edge -> no path.
    assert "no-trust-ned" not in {p.source for p in _paths()}


def test_role_still_reaches_admin_directly():
    admin = next(p for p in _paths() if p.source == "admin-role")
    assert admin.nodes == ["admin-role", ADMIN]


def test_account_root_trust_allows_same_account_caller():
    caller = Principal(name="c", arn="arn:aws:iam::999:user/c", ptype="user",
                       allowed_actions={"sts:AssumeRole"})
    role = Principal(name="r", arn="arn:aws:iam::999:role/r", ptype="role",
                     allowed_actions={"iam:AttachUserPolicy"},
                     trust_principals={"arn:aws:iam::999:root"})
    c = next(p for p in find_paths(Account(principals=[caller, role])) if p.source == "c")
    assert c.nodes == ["c", "r", ADMIN]


def test_caller_without_assume_permission_gets_no_edge():
    # trusted by the role, but lacks sts:AssumeRole -> both sides not satisfied.
    caller = Principal(name="c", arn="arn:aws:iam::999:user/c", ptype="user",
                       allowed_actions=set())
    role = Principal(name="r", arn="arn:aws:iam::999:role/r", ptype="role",
                     allowed_actions={"iam:AttachUserPolicy"},
                     trust_principals={"arn:aws:iam::999:user/c"})
    assert "c" not in {p.source for p in find_paths(Account(principals=[caller, role]))}
