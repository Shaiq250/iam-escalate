"""Tests for cross-principal escalation via user impersonation.

Creating another user's access key or console password lets a caller act
as that user. Modelled as an edge, so the caller reaches admin only when
the user it can take over actually reaches admin.
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import ADMIN, find_paths
from iam_escalate.hops import impersonate_edges
from iam_escalate.model import Account, Grant, Principal

FIXTURE = Path(__file__).parent.parent / "fixtures" / "impersonation_account.json"


def _paths():
    return find_paths(load_account_from_file(str(FIXTURE)))


def test_impersonation_chains_through_privileged_user():
    kim = next(p for p in _paths() if p.source == "keymaker-kim")
    assert kim.nodes == ["keymaker-kim", "admin-amy", ADMIN]
    assert "impersonate_user" in kim.hop_techniques[0]


def test_impersonation_does_not_route_through_harmless_user():
    kim = next(p for p in _paths() if p.source == "keymaker-kim")
    assert "harmless-hank" not in kim.nodes


def test_harmless_user_has_no_path():
    assert "harmless-hank" not in {p.source for p in _paths()}


def test_self_scoped_key_creates_no_edge():
    # A caller that can only create keys for its own user gets no edge.
    solo = Principal(name="solo", arn="arn:aws:iam::1:user/solo", ptype="user",
                     allow=[Grant(frozenset({"iam:CreateAccessKey"}),
                                  frozenset({"arn:aws:iam::1:user/solo"}))])
    other = Principal(name="other", arn="arn:aws:iam::1:user/other", ptype="user")
    assert impersonate_edges(Account(principals=[solo, other])) == []


def test_scoped_key_only_targets_the_named_user():
    caller = Principal(name="c", arn="arn:aws:iam::1:user/c", ptype="user",
                       allow=[Grant(frozenset({"iam:CreateAccessKey"}),
                                    frozenset({"arn:aws:iam::1:user/vip"}))])
    vip = Principal(name="vip", arn="arn:aws:iam::1:user/vip", ptype="user")
    bystander = Principal(name="bystander", arn="arn:aws:iam::1:user/bystander", ptype="user")
    edges = impersonate_edges(Account(principals=[caller, vip, bystander]))
    assert ("c", "vip", "impersonate_user") in edges
    assert not any(t == "bystander" for _, t, _ in edges)
