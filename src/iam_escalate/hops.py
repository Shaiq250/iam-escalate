"""Hop-based escalation edges (M4).

Direct rules answer "can this principal make itself admin?" Hop
generators answer "can this principal turn into another principal?",
producing principal -> principal edges. The graph search then chains
these with direct edges to discover multi-hop escalation paths.

AssumeRole is a two-sided handshake, and BOTH sides must line up:
  1. the caller must hold sts:AssumeRole (its own permissions), and
  2. the target role's trust policy must allow the caller.
Only then is there a real edge caller -> role.

v1 scope for trust matching: a caller is allowed if the role trusts it
by exact ARN, trusts the caller's whole account (an account-root ARN),
or trusts everyone ("*"). Federated/Service trusts and Condition-gated
trusts are out of scope here.
"""

from __future__ import annotations

from .model import Account, Principal, principal_can


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
        if not principal_can(caller, "sts:AssumeRole"):
            continue
        for role in roles:
            if role.name == caller.name:
                continue
            if _trust_allows(caller, role):
                edges.append((caller.name, role.name, "assume_role"))
    return edges
