"""Tests for cross-principal escalation via group membership.

iam:AddUserToGroup is modelled as an edge into a group node. The group's
own policies decide whether it reaches admin, so a caller escalates only
by joining a group that is actually privileged. A group is never a
standalone source, since it isn't an actor.
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import ADMIN, find_paths
from iam_escalate.hops import group_membership_edges
from iam_escalate.model import Account, Grant, Principal

FIXTURE = Path(__file__).parent.parent / "fixtures" / "group_escalation_account.json"


def _paths():
    return find_paths(load_account_from_file(str(FIXTURE)))


def test_add_to_group_chains_to_admin():
    joe = next(p for p in _paths() if p.source == "joiner-joe")
    assert joe.nodes == ["joiner-joe", "admins", ADMIN]
    assert "add_to_group" in joe.hop_techniques[0]


def test_group_is_not_a_standalone_source():
    assert "admins" not in {p.source for p in _paths()}


def test_group_node_carries_its_own_admin_capability():
    # The group reaches admin through its own inline policy (attach_user_policy).
    joe = next(p for p in _paths() if p.source == "joiner-joe")
    assert "attach_user_policy" in joe.hop_techniques[1]


def _group(name):
    return Principal(name=name, arn=f"arn:aws:iam::1:group/{name}", ptype="group")


def test_edge_requires_the_permission_on_that_group():
    caller = Principal(name="c", arn="arn:aws:iam::1:user/c", ptype="user",
                       allow=[Grant(frozenset({"iam:AddUserToGroup"}),
                                    frozenset({"arn:aws:iam::1:group/admins"}))])
    admins, others = _group("admins"), _group("others")
    edges = group_membership_edges(Account(principals=[caller, admins, others]))
    assert ("c", "admins", "add_to_group") in edges
    assert not any(t == "others" for _, t, _ in edges)


def test_role_caller_gets_no_group_edge():
    role = Principal(name="r", arn="arn:aws:iam::1:role/r", ptype="role",
                     allowed_actions={"iam:AddUserToGroup"})
    admins = _group("admins")
    assert group_membership_edges(Account(principals=[role, admins])) == []
