"""Tests for the batched direct-escalation rules:
create_access_key, login_profile (create/update), set_default_policy_version.
"""

from iam_escalate.engine import analyze
from iam_escalate.model import Account, Principal


def _user(name, allowed, denied=()):
    return Principal(name=name, arn=f"arn:aws:iam::123:user/{name}", ptype="user",
                     allowed_actions=set(allowed), denied_actions=set(denied))


def _rule_ids_for(principal_name, principals):
    return {f.rule_id for f in analyze(Account(principals=principals)) if f.principal == principal_name}


# --- create_access_key ---

def test_create_access_key_is_flagged():
    assert "create_access_key" in _rule_ids_for("k", [_user("k", {"iam:CreateAccessKey"})])


def test_create_access_key_deny_blocks():
    u = _user("k", {"iam:CreateAccessKey"}, {"iam:CreateAccessKey"})
    assert "create_access_key" not in _rule_ids_for("k", [u])


# --- login_profile (both permissions map to the same rule) ---

def test_create_login_profile_is_flagged():
    assert "login_profile" in _rule_ids_for("p", [_user("p", {"iam:CreateLoginProfile"})])


def test_update_login_profile_is_flagged():
    assert "login_profile" in _rule_ids_for("p", [_user("p", {"iam:UpdateLoginProfile"})])


def test_login_profile_unrelated_not_flagged():
    assert "login_profile" not in _rule_ids_for("p", [_user("p", {"iam:GetLoginProfile"})])


# --- set_default_policy_version ---

def test_set_default_policy_version_is_flagged():
    assert "set_default_policy_version" in _rule_ids_for("v", [_user("v", {"iam:SetDefaultPolicyVersion"})])


def test_wildcard_covers_all_three():
    ids = _rule_ids_for("wild", [_user("wild", {"iam:*"})])
    assert {"create_access_key", "login_profile", "set_default_policy_version"} <= ids
