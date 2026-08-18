"""Tests for permission boundaries (post-v1 correctness item).

A permission boundary caps a principal's effective permissions to the
intersection of its identity policies and the boundary. An admin-capable
identity policy behind a restrictive boundary must NOT be reported as an
escalation.
"""

from pathlib import Path

from iam_escalate.collector import load_account_from_file
from iam_escalate.graph import find_paths
from iam_escalate.model import Account, Grant, Principal, principal_can

FIXTURE = Path(__file__).parent.parent / "fixtures" / "boundaries_account.json"


def test_boundary_prevents_false_escalation():
    sources = {p.source for p in find_paths(load_account_from_file(str(FIXTURE)))}
    assert "capped-cathy" not in sources  # admin-capable policy, but boundary is S3-only


def test_without_boundary_still_escalates():
    sources = {p.source for p in find_paths(load_account_from_file(str(FIXTURE)))}
    assert "uncapped-uma" in sources  # same policy, no boundary


def _p(allow, boundary_allow=None, boundary_deny=()):
    return Principal(
        name="p", arn="arn:aws:iam::1:user/p", ptype="user",
        allow=[Grant(frozenset(a), frozenset(r)) for a, r in allow],
        boundary_allow=None if boundary_allow is None else [Grant(frozenset(a), frozenset(r)) for a, r in boundary_allow],
        boundary_deny=[Grant(frozenset(a), frozenset(r)) for a, r in boundary_deny],
    )


def test_boundary_caps_to_intersection():
    p = _p(allow=[({"iam:AttachUserPolicy"}, {"*"})], boundary_allow=[({"s3:*"}, {"*"})])
    assert not principal_can(p, "iam:AttachUserPolicy")  # not in the boundary


def test_boundary_allowing_action_permits_it():
    p = _p(allow=[({"iam:AttachUserPolicy"}, {"*"})], boundary_allow=[({"iam:*"}, {"*"})])
    assert principal_can(p, "iam:AttachUserPolicy")  # allowed by both


def test_boundary_deny_blocks():
    p = _p(allow=[({"iam:AttachUserPolicy"}, {"*"})],
           boundary_allow=[({"*"}, {"*"})],
           boundary_deny=[({"iam:AttachUserPolicy"}, {"*"})])
    assert not principal_can(p, "iam:AttachUserPolicy")


def test_no_boundary_is_no_cap():
    p = _p(allow=[({"iam:AttachUserPolicy"}, {"*"})])  # boundary_allow None
    assert principal_can(p, "iam:AttachUserPolicy")
