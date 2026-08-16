"""Technique: iam:CreatePolicyVersion self-escalation.

If a user can call iam:CreatePolicyVersion on a customer-managed policy
that applies to it, the user can publish a NEW version of that policy
granting full admin and mark it the default version -- upgrading its own
permissions without attaching anything new. A classic Rhino Security Labs
method; like attach_user_policy it's a direct edge to admin, so no graph
is needed.

Note (v1 scope): this flags the capability -- holding the permission --
rather than proving a specific attached, editable policy exists. Tying it
to a concrete policy the user can actually edit is a precision refinement
for later; over-flagging a real, dangerous permission is the safe default.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register


@register
class CreatePolicyVersion(Rule):
    id = "create_policy_version"
    name = "Publish a new admin policy version (iam:CreatePolicyVersion)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        if not principal_can(principal, "iam:CreatePolicyVersion"):
            return None

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            principal=principal.name,
            escalates_to="AdministratorAccess",
            explanation=(
                f"{principal.name} can call iam:CreatePolicyVersion, so it can publish a new "
                f"version of a customer-managed policy that applies to it -- containing full "
                f"admin permissions -- and set it as the default, escalating its own access."
            ),
            exploit_command=(
                "aws iam create-policy-version --policy-arn <attached-policy-arn> "
                "--policy-document file://admin.json --set-as-default"
            ),
            remediation=(
                f"Remove iam:CreatePolicyVersion from {principal.name}, or restrict it with a "
                f"permissions boundary / condition so it cannot rewrite privileged policies."
            ),
        )
