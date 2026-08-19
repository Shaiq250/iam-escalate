"""Tests for the batched direct-escalation rule set_default_policy_version.

(create_access_key and login_profile used to live here too; they're now
modelled as impersonation hop edges, see test_impersonation.py.)
"""

from iam_escalate.engine import analyze
from iam_escalate.model import Account, Principal


def _user(name, allowed, denied=()):
    return Principal(name=name, arn=f"arn:aws:iam::123:user/{name}", ptype="user",
                     allowed_actions=set(allowed), denied_actions=set(denied))


def _rule_ids_for(principal_name, principals):
    return {f.rule_id for f in analyze(Account(principals=principals)) if f.principal == principal_name}


def test_set_default_policy_version_is_flagged():
    assert "set_default_policy_version" in _rule_ids_for("v", [_user("v", {"iam:SetDefaultPolicyVersion"})])


def test_set_default_policy_version_deny_blocks():
    u = _user("v", {"iam:SetDefaultPolicyVersion"}, {"iam:SetDefaultPolicyVersion"})
    assert "set_default_policy_version" not in _rule_ids_for("v", [u])


def test_wildcard_covers_set_default_policy_version():
    ids = _rule_ids_for("wild", [_user("wild", {"iam:*"})])
    assert "set_default_policy_version" in ids
