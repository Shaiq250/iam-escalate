"""Tests for attached-managed-policy resolution (2b).

A permission that reaches a user through an attached managed policy must
be resolved from the dump's Policies list and count toward escalation
detection. A policy whose document isn't in the dump must be flagged in
unresolved_policies, not silently dropped or crashed on.
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.engine import analyze

FIXTURE = Path(__file__).parent.parent / "fixtures" / "managed_policy_account.json"


def test_escalation_via_managed_policy_is_detected():
    findings = analyze(load_account_from_file(str(FIXTURE)))
    flagged = {f.principal for f in findings}
    assert "mgr-mike" in flagged  # iam:AttachUserPolicy came from a managed policy


def test_managed_policy_actions_reach_the_principal():
    account = load_account_from_file(str(FIXTURE))
    mike = next(p for p in account.principals if p.name == "mgr-mike")
    assert "iam:AttachUserPolicy" in mike.allowed_actions


def test_unresolvable_policy_is_flagged():
    account = load_account_from_file(str(FIXTURE))
    olly = next(p for p in account.principals if p.name == "opaque-olly")
    assert "MysteryPolicy" in olly.unresolved_policies


def test_unresolvable_policy_does_not_create_false_finding():
    findings = analyze(load_account_from_file(str(FIXTURE)))
    assert "opaque-olly" not in {f.principal for f in findings}
