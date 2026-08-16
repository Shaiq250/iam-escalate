"""Technique: iam:SetDefaultPolicyVersion self-escalation.

If a user can call iam:SetDefaultPolicyVersion on a customer-managed
policy that applies to it, it can switch the policy's default to an older
version that grants more permissions -- without writing any new policy.
Sibling of create_policy_version (which authors a new admin version);
this one reuses an existing more-permissive version. Classic Rhino
Security Labs method; a direct edge, no graph needed.

Note (v1 scope): flags the capability rather than proving a more-
permissive older version exists on an applicable policy.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register


@register
class SetDefaultPolicyVersion(Rule):
    id = "set_default_policy_version"
    name = "Roll a policy to a more-permissive version (iam:SetDefaultPolicyVersion)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        if not principal_can(principal, "iam:SetDefaultPolicyVersion"):
            return None

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            principal=principal.name,
            escalates_to="AdministratorAccess",
            explanation=(
                f"{principal.name} can call iam:SetDefaultPolicyVersion, so it can switch a "
                f"customer-managed policy that applies to it back to an older, more-permissive "
                f"version, escalating its own access."
            ),
            exploit_command=(
                "aws iam set-default-policy-version --policy-arn <attached-policy-arn> "
                "--version-id <more-permissive-version>"
            ),
            remediation=(
                f"Remove iam:SetDefaultPolicyVersion from {principal.name}, or restrict it with "
                f"a permissions boundary / condition so it cannot alter privileged policies."
            ),
        )
