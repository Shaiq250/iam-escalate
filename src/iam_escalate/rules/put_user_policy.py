"""Technique: iam:PutUserPolicy self-escalation.

If a user can call iam:PutUserPolicy, it can write a new INLINE policy
directly onto itself granting full admin -- no existing policy needed,
unlike attach_user_policy (which attaches a managed policy) or
create_policy_version (which rewrites one). A classic Rhino Security Labs
method; a direct edge to admin, so no graph is needed.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register


@register
class PutUserPolicy(Rule):
    id = "put_user_policy"
    name = "Inject an inline admin policy (iam:PutUserPolicy)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        if not principal_can(principal, "iam:PutUserPolicy"):
            return None

        target = principal.name if principal.ptype == "user" else "<your-user>"
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            principal=principal.name,
            escalates_to="AdministratorAccess",
            explanation=(
                f"{principal.name} can call iam:PutUserPolicy, so it can write a new inline "
                f"policy onto itself granting full admin ('*' on '*'), escalating its own access."
            ),
            exploit_command=(
                f"aws iam put-user-policy --user-name {target} "
                f"--policy-name esc --policy-document "
                f"'{{\"Version\":\"2012-10-17\",\"Statement\":"
                f"[{{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}}]}}'"
            ),
            remediation=(
                f"Remove iam:PutUserPolicy from {principal.name}, or restrict it with a "
                f"permissions boundary / condition so it cannot self-grant privileges."
            ),
        )
