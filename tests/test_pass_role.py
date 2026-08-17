"""Tests for PassRole hop edges and their multi-hop paths (M4 4c)."""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import ADMIN, find_paths
from iam_escalate.model import Account, Principal

FIXTURE = Path(__file__).parent.parent / "fixtures" / "pass_role_chain_account.json"


def _paths():
    return find_paths(load_account_from_file(str(FIXTURE)))


def test_pass_role_lambda_multi_hop():
    larry = next((p for p in _paths() if p.source == "lambda-larry"), None)
    assert larry is not None
    assert larry.nodes == ["lambda-larry", "powerful-role", ADMIN]
    assert "pass_role_lambda" in larry.hop_techniques[0]


def test_pass_role_without_compute_has_no_edge():
    # harry can PassRole but can't create a Lambda/EC2 to run it -> no edge.
    assert "half-harry" not in {p.source for p in _paths()}


def test_pass_role_ec2_variant():
    caller = Principal(name="c", arn="arn:aws:iam::999:user/c", ptype="user",
                       allowed_actions={"iam:PassRole", "ec2:RunInstances"})
    role = Principal(name="r", arn="arn:aws:iam::999:role/r", ptype="role",
                     allowed_actions={"iam:AttachUserPolicy"})
    c = next(p for p in find_paths(Account(principals=[caller, role])) if p.source == "c")
    assert c.nodes == ["c", "r", ADMIN]
    assert "pass_role_ec2" in c.hop_techniques[0]


def test_pass_role_alone_is_not_enough():
    caller = Principal(name="c", arn="arn:aws:iam::999:user/c", ptype="user",
                       allowed_actions={"iam:PassRole"})
    role = Principal(name="r", arn="arn:aws:iam::999:role/r", ptype="role",
                     allowed_actions={"iam:AttachUserPolicy"})
    assert "c" not in {p.source for p in find_paths(Account(principals=[caller, role]))}
