"""Technique: iam:AttachUserPolicy self-escalation.

If a user can attach a managed policy to itself, it can attach
AdministratorAccess and become admin. This is one of the classic
Rhino Security Labs escalation methods and a good first rule because
it needs no graph — it's a direct edge to admin.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


@register
class AttachUserPolicy(Rule):
    id = "attach_user_policy"
    name = "Self-attach a managed admin policy (iam:AttachUserPolicy)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        if principal.ptype != "user":
            return None
        if not principal_can(principal, "iam:AttachUserPolicy"):
            return None

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            principal=principal.name,
            escalates_to="AdministratorAccess",
            explanation=(
                f"{principal.name} can call iam:AttachUserPolicy, so it can attach "
                f"the AWS-managed AdministratorAccess policy to itself and gain full admin."
            ),
            exploit_command=(
                f"aws iam attach-user-policy --user-name {principal.name} "
                f"--policy-arn {ADMIN_ARN}"
            ),
            remediation=(
                f"Remove iam:AttachUserPolicy from {principal.name}, or scope it with a "
                f"permissions boundary / condition so it cannot attach privileged policies."
            ),
        )
