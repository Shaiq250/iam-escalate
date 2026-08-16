"""Technique: iam:CreateAccessKey self-escalation.

If a user can call iam:CreateAccessKey against another (more privileged)
user, it can mint a fresh access key for that user and act as them. A
classic Rhino Security Labs method; a direct edge to a stronger identity,
so no graph is needed.

Note (v1 scope): flags the capability -- holding the permission -- rather
than proving a more-privileged target user exists. Correlating it with a
concrete higher-privilege target is a precision refinement for later.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register


@register
class CreateAccessKey(Rule):
    id = "create_access_key"
    name = "Mint access keys for another user (iam:CreateAccessKey)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        if principal.ptype != "user":
            return None
        if not principal_can(principal, "iam:CreateAccessKey"):
            return None

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            principal=principal.name,
            escalates_to="a more-privileged user",
            explanation=(
                f"{principal.name} can call iam:CreateAccessKey, so it can create a new access "
                f"key for a more-privileged user and authenticate as that user."
            ),
            exploit_command=(
                "aws iam create-access-key --user-name <privileged-target-user>"
            ),
            remediation=(
                f"Scope iam:CreateAccessKey on {principal.name} to its own user only (a "
                f"condition on the resource/username), or remove it."
            ),
        )
