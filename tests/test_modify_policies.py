"""Tests for the role/group policy-write escalation rules."""

from iam_escalate.engine import analyze
from iam_escalate.model import Account, Principal


def _user(name, allowed, denied=()):
    return Principal(name=name, arn=f"arn:aws:iam::123:user/{name}", ptype="user",
                     allowed_actions=set(allowed), denied_actions=set(denied))


def _rule_ids(name, principals):
    return {f.rule_id for f in analyze(Account(principals=principals)) if f.principal == name}


def test_put_role_policy_flags_modify_role():
    assert "modify_role_policy" in _rule_ids("u", [_user("u", {"iam:PutRolePolicy"})])


def test_attach_role_policy_flags_modify_role():
    assert "modify_role_policy" in _rule_ids("u", [_user("u", {"iam:AttachRolePolicy"})])


def test_put_group_policy_flags_modify_group():
    assert "modify_group_policy" in _rule_ids("u", [_user("u", {"iam:PutGroupPolicy"})])


def test_attach_group_policy_flags_modify_group():
    assert "modify_group_policy" in _rule_ids("u", [_user("u", {"iam:AttachGroupPolicy"})])


def test_unrelated_permission_not_flagged():
    ids = _rule_ids("u", [_user("u", {"iam:GetRole"})])
    assert "modify_role_policy" not in ids and "modify_group_policy" not in ids


def test_deny_blocks_role_policy_write():
    u = _user("u", {"iam:PutRolePolicy"}, {"iam:PutRolePolicy"})
    assert "modify_role_policy" not in _rule_ids("u", [u])


def test_wildcard_covers_both():
    ids = _rule_ids("wild", [_user("wild", {"iam:*"})])
    assert {"modify_role_policy", "modify_group_policy"} <= ids
