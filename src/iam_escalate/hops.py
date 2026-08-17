"""Hop-based escalation edges (M4).

Direct rules answer "can this principal make itself admin?" Hop
generators answer "can this principal turn into another principal?",
producing principal -> principal edges. The graph search then chains
these with direct edges to discover multi-hop escalation paths.

Two hop families, gated differently:

  AssumeRole -- a two-sided handshake:
    1. the caller must hold sts:AssumeRole, and
    2. the target role's trust policy must allow the caller.

  PassRole -- gated purely on the CALLER's permissions (the target
  role's trust policy is not consulted): the caller must hold
  iam:PassRole AND a compute-creation action (lambda:CreateFunction or
  ec2:RunInstances), letting it hand a powerful role to code it controls.

v1 scope: resources are not modelled, so a caller with iam:PassRole is
treated as able to pass any role, and sts:AssumeRole as able to target
any trusting role. This over-approximates -- the honest, finder-friendly
default (flag for review rather than miss), noted in the README.
"""

from __future__ import annotations

from .model import Account, Principal, principal_can

# compute-creation action -> technique label for PassRole
_PASS_ROLE_SERVICES = {
    "lambda:CreateFunction": "pass_role_lambda",
    "ec2:RunInstances": "pass_role_ec2",
}


def _account_id(arn: str) -> str | None:
    # arn:aws:iam::123456789012:user/name  ->  123456789012
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _trust_allows(caller: Principal, role: Principal) -> bool:
    """Does `role`'s trust policy permit `caller` to assume it?"""
    trust = role.trust_principals
    if "*" in trust:
        return True
    if caller.arn in trust:
        return True
    account = _account_id(caller.arn)
    return bool(account) and f"arn:aws:iam::{account}:root" in trust


def assume_role_edges(account: Account) -> list[tuple[str, str, str]]:
    """(source, target, technique) edges for sts:AssumeRole role assumption."""
    roles = [p for p in account.principals if p.ptype == "role"]
    edges: list[tuple[str, str, str]] = []
    for caller in account.principals:
        for role in roles:
            if role.name == caller.name:
                continue
            # Both sides: caller may assume THIS role's ARN, and the role trusts the caller.
            if principal_can(caller, "sts:AssumeRole", role.arn) and _trust_allows(caller, role):
                edges.append((caller.name, role.name, "assume_role"))
    return edges


def pass_role_edges(account: Account) -> list[tuple[str, str, str]]:
    """(source, target, technique) edges for iam:PassRole + compute creation."""
    roles = [p for p in account.principals if p.ptype == "role"]
    edges: list[tuple[str, str, str]] = []
    for caller in account.principals:
        # Compute-creation is a general capability (not role-specific).
        techniques = [
            tech for action, tech in _PASS_ROLE_SERVICES.items()
            if principal_can(caller, action)
        ]
        if not techniques:
            continue  # can't run anything, so PassRole leads nowhere
        for role in roles:
            if role.name == caller.name:
                continue
            # PassRole must cover THIS specific role's ARN.
            if not principal_can(caller, "iam:PassRole", role.arn):
                continue
            for tech in techniques:
                edges.append((caller.name, role.name, tech))
    return edges


def all_hop_edges(account: Account) -> list[tuple[str, str, str]]:
    """Every hop edge from every generator."""
    return assume_role_edges(account) + pass_role_edges(account)
