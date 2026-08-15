"""Tests for the AttachUserPolicy rule and the analysis pipeline.

Every technique gets its own test like this. Because analysis runs
against fixture JSON, the whole suite is deterministic and needs no
AWS account.
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.engine import analyze

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sample_account.json"


def test_vulnerable_user_is_flagged():
    account = load_account_from_file(str(FIXTURE))
    findings = analyze(account)

    flagged = {f.principal for f in findings}
    assert "dev-intern" in flagged  # has iam:AttachUserPolicy -> can self-admin


def test_readonly_user_is_not_flagged():
    account = load_account_from_file(str(FIXTURE))
    findings = analyze(account)

    flagged = {f.principal for f in findings}
    assert "readonly-bob" not in flagged  # read-only, no escalation


def test_finding_has_exploit_and_remediation():
    account = load_account_from_file(str(FIXTURE))
    finding = next(f for f in analyze(account) if f.principal == "dev-intern")

    assert "attach-user-policy" in finding.exploit_command
    assert finding.remediation  # non-empty
    assert finding.severity == "HIGH"
