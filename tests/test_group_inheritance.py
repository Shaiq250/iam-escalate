"""Tests for group-inherited permissions (2c).

A user inherits its groups' policies. This must compose with the earlier
sources: a group can grant an escalation through its own managed policy,
and a user-level explicit Deny must still override a group-granted Allow.
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.engine import analyze
from iam_escalate.model import principal_can

FIXTURE = Path(__file__).parent.parent / "fixtures" / "group_inheritance_account.json"


def test_escalation_inherited_from_group_is_detected():
    findings = analyze(load_account_from_file(str(FIXTURE)))
    assert "grp-gary" in {f.principal for f in findings}


def test_group_managed_policy_action_reaches_member():
    account = load_account_from_file(str(FIXTURE))
    gary = next(p for p in account.principals if p.name == "grp-gary")
    # Permission came from the group's ATTACHED MANAGED policy, resolved via the index.
    assert principal_can(gary, "iam:AttachUserPolicy")


def test_user_deny_overrides_group_allow():
    findings = analyze(load_account_from_file(str(FIXTURE)))
    # carl inherits the allow from the group but denies it on himself -> deny wins.
    assert "capped-carl" not in {f.principal for f in findings}
