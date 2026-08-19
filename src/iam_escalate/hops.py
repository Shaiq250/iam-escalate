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

from .model import Account, Principal, action_matches, principal_can, resource_matches

# compute-creation action -> technique label for PassRole
# compute-creation action -> (technique label, the service the role is passed to)
_PASS_ROLE_SERVICES = {
    "lambda:CreateFunction": ("pass_role_lambda", "lambda.amazonaws.com"),
    "ec2:RunInstances": ("pass_role_ec2", "ec2.amazonaws.com"),
    "glue:CreateDevEndpoint": ("pass_role_glue", "glue.amazonaws.com"),
    "cloudformation:CreateStack": ("pass_role_cloudformation", "cloudformation.amazonaws.com"),
    "datapipeline:CreatePipeline": ("pass_role_datapipeline", "datapipeline.amazonaws.com"),
    "ecs:RunTask": ("pass_role_ecs", "ecs-tasks.amazonaws.com"),
    "codebuild:CreateProject": ("pass_role_codebuild", "codebuild.amazonaws.com"),
    "sagemaker:CreateNotebookInstance": ("pass_role_sagemaker", "sagemaker.amazonaws.com"),
}


def _passrole_services_for(caller: Principal, role_arn: str) -> frozenset[str] | None | set:
    """Which services may `caller` pass `role_arn` to?

    Returns None when a PassRole grant is unrestricted (any service), a set
    of allowed service principals when every matching grant is limited by
    iam:PassedToService, or an empty set when the caller can't pass this
    role at all. principal_can already applies deny and boundary.
    """
    if not principal_can(caller, "iam:PassRole", role_arn):
        return set()
    allowed: set[str] = set()
    for g in caller.allow:
        if not any(action_matches(a, "iam:PassRole") for a in g.actions):
            continue
        if not any(resource_matches(r, role_arn) for r in g.resources):
            continue
        if g.passed_to_services is None:
            return None  # an unrestricted grant covers any service
        allowed |= set(g.passed_to_services)
    return allowed


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
    """(source, target, technique) edges for iam:PassRole + compute creation.

    Honours iam:PassedToService: if the PassRole grant is limited to certain
    services, only the matching compute techniques produce an edge.
    """
    roles = [p for p in account.principals if p.ptype == "role"]
    edges: list[tuple[str, str, str]] = []
    for caller in account.principals:
        # Compute-creation is a general capability (not role-specific).
        compute = [
            (tech, service) for action, (tech, service) in _PASS_ROLE_SERVICES.items()
            if principal_can(caller, action)
        ]
        if not compute:
            continue  # can't run anything, so PassRole leads nowhere
        for role in roles:
            if role.name == caller.name:
                continue
            allowed_services = _passrole_services_for(caller, role.arn)
            if allowed_services is not None and not allowed_services:
                continue  # can't pass this role at all
            for tech, service in compute:
                if allowed_services is None or service in allowed_services:
                    edges.append((caller.name, role.name, tech))
    return edges


def update_trust_edges(account: Account) -> list[tuple[str, str, str]]:
    """(source, target, technique) edges for rewriting a role's trust policy.

    A caller holding iam:UpdateAssumeRolePolicy on a role can rewrite that
    role's trust to allow itself, then assume it. Unlike a plain
    AssumeRole hop, the role's current trust doesn't need to allow the
    caller, since the caller edits it. The caller still needs
    sts:AssumeRole to make the assume call afterwards. Both checks are
    scoped to the target role's ARN.
    """
    roles = [p for p in account.principals if p.ptype == "role"]
    edges: list[tuple[str, str, str]] = []
    for caller in account.principals:
        for role in roles:
            if role.name == caller.name:
                continue
            if principal_can(caller, "iam:UpdateAssumeRolePolicy", role.arn) and \
                    principal_can(caller, "sts:AssumeRole", role.arn):
                edges.append((caller.name, role.name, "update_trust_policy"))
    return edges


_IMPERSONATE_ACTIONS = ("iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile")


def impersonate_edges(account: Account) -> list[tuple[str, str, str]]:
    """(source, target, technique) edges for taking over another user.

    If a caller can create an access key, or set or reset the console
    password, for a different user, it can authenticate as that user and
    inherit whatever that user can reach. The permission is scoped to the
    target user's ARN, so a caller limited to its own user produces no
    edge, and the caller only reaches admin when the user it can take over
    actually reaches admin.
    """
    users = [p for p in account.principals if p.ptype == "user"]
    edges: list[tuple[str, str, str]] = []
    for caller in account.principals:
        for target in users:
            if target.name == caller.name:
                continue
            if any(principal_can(caller, action, target.arn) for action in _IMPERSONATE_ACTIONS):
                edges.append((caller.name, target.name, "impersonate_user"))
    return edges


def all_hop_edges(account: Account) -> list[tuple[str, str, str]]:
    """Every hop edge from every generator."""
    return (
        assume_role_edges(account)
        + pass_role_edges(account)
        + update_trust_edges(account)
        + impersonate_edges(account)
    )
