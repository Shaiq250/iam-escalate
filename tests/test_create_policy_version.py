"""Tests for the iam:CreatePolicyVersion escalation rule."""

from iam_escalate.engine import analyze
from iam_escalate.model import Account, Principal


def _user(name, allowed):
    return Principal(name=name, arn=f"arn:aws:iam::123:user/{name}", ptype="user",
                     allowed_actions=set(allowed))


def test_create_policy_version_is_flagged():
    account = Account(principals=[_user("polly", {"iam:CreatePolicyVersion"})])
    flagged = {(f.principal, f.rule_id) for f in analyze(account)}
    assert ("polly", "create_policy_version") in flagged


def test_unrelated_permission_is_not_flagged():
    account = Account(principals=[_user("reader", {"iam:ListPolicies"})])
    assert analyze(account) == []


def test_wildcard_covers_the_action():
    account = Account(principals=[_user("wild", {"iam:*"})])
    flagged = {(f.principal, f.rule_id) for f in analyze(account)}
    assert ("wild", "create_policy_version") in flagged


def test_explicit_deny_blocks_it():
    p = Principal(name="denied", arn="arn:aws:iam::123:user/denied", ptype="user",
                  allowed_actions={"iam:CreatePolicyVersion"},
                  denied_actions={"iam:CreatePolicyVersion"})
    account = Account(principals=[p])
    assert all(f.rule_id != "create_policy_version" for f in analyze(account))
