"""Tests for iam:PassedToService handling (the one condition the tool evaluates).

A PassRole grant limited to a service should only enable that service's
hop, even when the caller can create other kinds of compute. All other
conditions stay flagged under "Not fully evaluated".
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import find_paths

FIXTURE = Path(__file__).parent.parent / "fixtures" / "passedtoservice_account.json"


def _lily_path():
    account = load_account_from_file(str(FIXTURE))
    return next(p for p in find_paths(account) if p.source == "lambda-only-lily")


def test_passrole_limited_to_lambda_enables_only_lambda():
    hop0 = _lily_path().hop_techniques[0]
    assert "pass_role_lambda" in hop0


def test_passrole_limited_to_lambda_blocks_ecs():
    # lily can ecs:RunTask, but the PassRole condition forbids passing to ECS.
    for techs in _lily_path().hop_techniques:
        assert "pass_role_ecs" not in techs


def test_only_passedtoservice_condition_is_not_flagged():
    account = load_account_from_file(str(FIXTURE))
    lily = next(p for p in account.principals if p.name == "lambda-only-lily")
    # The only condition present is iam:PassedToService, which we handle.
    assert lily.has_conditions is False
