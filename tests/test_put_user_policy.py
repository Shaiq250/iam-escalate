"""Tests for the iam:PutUserPolicy escalation rule."""

from iam_escalate.engine import analyze
from iam_escalate.model import Account, Principal


def _user(name, allowed, denied=()):
    return Principal(name=name, arn=f"arn:aws:iam::123:user/{name}", ptype="user",
                     allowed_actions=set(allowed), denied_actions=set(denied))


def test_put_user_policy_is_flagged():
    account = Account(principals=[_user("polly", {"iam:PutUserPolicy"})])
    flagged = {(f.principal, f.rule_id) for f in analyze(account)}
    assert ("polly", "put_user_policy") in flagged


def test_unrelated_permission_is_not_flagged():
    account = Account(principals=[_user("reader", {"iam:GetUser"})])
    assert all(f.rule_id != "put_user_policy" for f in analyze(account))


def test_wildcard_covers_the_action():
    account = Account(principals=[_user("wild", {"iam:*"})])
    flagged = {(f.principal, f.rule_id) for f in analyze(account)}
    assert ("wild", "put_user_policy") in flagged


def test_explicit_deny_blocks_it():
    account = Account(principals=[_user("denied", {"iam:PutUserPolicy"}, {"iam:PutUserPolicy"})])
    assert all(f.rule_id != "put_user_policy" for f in analyze(account))
