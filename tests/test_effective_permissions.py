"""Tests for effective-permission logic in principal_can.

Effective permission = allowed AND not explicitly denied. An explicit
Deny overrides any Allow, matching real IAM evaluation.
"""

from iam_escalate.model import Principal, principal_can


def _p(allowed, denied=()):
    return Principal(
        name="p",
        arn="arn:aws:iam::123:user/p",
        ptype="user",
        allowed_actions=set(allowed),
        denied_actions=set(denied),
    )


def test_allow_only_is_permitted():
    assert principal_can(_p({"iam:AttachUserPolicy"}), "iam:AttachUserPolicy")


def test_no_allow_is_not_permitted():
    assert not principal_can(_p({"s3:GetObject"}), "iam:AttachUserPolicy")


def test_explicit_deny_overrides_matching_allow():
    p = _p({"iam:AttachUserPolicy"}, {"iam:AttachUserPolicy"})
    assert not principal_can(p, "iam:AttachUserPolicy")


def test_wildcard_deny_blocks_specific_allow():
    p = _p({"iam:AttachUserPolicy"}, {"iam:*"})
    assert not principal_can(p, "iam:AttachUserPolicy")


def test_star_deny_blocks_everything():
    p = _p({"iam:AttachUserPolicy"}, {"*"})
    assert not principal_can(p, "iam:AttachUserPolicy")


def test_wildcard_allow_without_deny_is_permitted():
    assert principal_can(_p({"*"}), "iam:AttachUserPolicy")
