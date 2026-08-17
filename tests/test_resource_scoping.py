"""Tests for the resource-aware permission model (resource scoping, step 1)."""

from iam_escalate.model import Grant, Principal, principal_can, resource_matches


def test_resource_matches_star():
    assert resource_matches("*", "arn:aws:iam::1:role/anything")


def test_resource_matches_prefix_wildcard():
    assert resource_matches("arn:aws:iam::1:role/dev-*", "arn:aws:iam::1:role/dev-team")
    assert not resource_matches("arn:aws:iam::1:role/dev-*", "arn:aws:iam::1:role/admin")


def test_resource_matches_single_char():
    assert resource_matches("arn:aws:iam::1:role/dev-?", "arn:aws:iam::1:role/dev-1")
    assert not resource_matches("arn:aws:iam::1:role/dev-?", "arn:aws:iam::1:role/dev-99")


def _p(allow=(), deny=()):
    return Principal(name="p", arn="arn:aws:iam::1:user/p", ptype="user",
                     allow=list(allow), deny=list(deny))


def test_resource_scoped_allow():
    p = _p(allow=[Grant(frozenset({"iam:PassRole"}), frozenset({"arn:aws:iam::1:role/dev-*"}))])
    assert principal_can(p, "iam:PassRole", "arn:aws:iam::1:role/dev-x")
    assert not principal_can(p, "iam:PassRole", "arn:aws:iam::1:role/admin")


def test_resource_none_is_action_only():
    p = _p(allow=[Grant(frozenset({"iam:PassRole"}), frozenset({"arn:aws:iam::1:role/dev-*"}))])
    # No specific target -> "does the action exist at all?"
    assert principal_can(p, "iam:PassRole")


def test_resource_scoped_deny_overrides():
    p = _p(
        allow=[Grant(frozenset({"iam:PassRole"}), frozenset({"*"}))],
        deny=[Grant(frozenset({"iam:PassRole"}), frozenset({"arn:aws:iam::1:role/admin"}))],
    )
    assert principal_can(p, "iam:PassRole", "arn:aws:iam::1:role/dev")       # allowed
    assert not principal_can(p, "iam:PassRole", "arn:aws:iam::1:role/admin")  # denied on this one


def test_legacy_action_set_folds_to_star():
    # Passing allowed_actions still works and behaves as "on any resource".
    p = Principal(name="p", arn="arn:aws:iam::1:user/p", ptype="user",
                  allowed_actions={"sts:AssumeRole"})
    assert principal_can(p, "sts:AssumeRole", "arn:aws:iam::1:role/whatever")
    assert principal_can(p, "sts:AssumeRole")


# --- step 2: resource-scoped hop edges (end to end) ---

from pathlib import Path  # noqa: E402

from iam_escalate.collector import load_account_from_file  # noqa: E402
from iam_escalate.graph import find_paths  # noqa: E402

SCOPED = Path(__file__).parent.parent / "fixtures" / "scoped_passrole_account.json"


def test_scoped_passrole_reaches_matching_role():
    # sam can PassRole on role/dev-*  -> should reach dev-runner (which is admin-capable).
    sources = {p.source for p in find_paths(load_account_from_file(str(SCOPED)))}
    assert "scoped-sam" in sources


def test_scoped_passrole_does_not_reach_nonmatching_role():
    # The path must go through dev-runner, NOT admin-role (dev-* doesn't match it).
    paths = find_paths(load_account_from_file(str(SCOPED)))
    sam = next(p for p in paths if p.source == "scoped-sam")
    assert "dev-runner" in sam.nodes
    assert "admin-role" not in sam.nodes


def test_star_passrole_still_reaches_admin():
    # Regression: an unscoped PassRole chain (existing fixture) still works.
    sources = {p.source for p in find_paths(
        load_account_from_file(str(Path(__file__).parent.parent / "fixtures" / "pass_role_chain_account.json"))
    )}
    assert "lambda-larry" in sources
