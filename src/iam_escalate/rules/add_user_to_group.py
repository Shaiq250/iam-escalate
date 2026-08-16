"""Technique: iam:AddUserToGroup self-escalation.

If a user can call iam:AddUserToGroup, it can add itself to a group that
carries privileged (e.g. admin) policies and inherit that access. A
classic Rhino Security Labs method; a direct edge to admin, so no graph
is needed.

Note (v1 scope): this flags the capability -- holding the permission --
rather than proving a privileged group exists to join. Correlating it
with an actual admin-carrying group is a precision refinement for later;
flagging a real, dangerous permission is the safe default.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register


@register
class AddUserToGroup(Rule):
    id = "add_user_to_group"
    name = "Add self to a privileged group (iam:AddUserToGroup)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        if not principal_can(principal, "iam:AddUserToGroup"):
            return None

        return Finding(
            rule_id=self.id,
            severity=self.severity,
            principal=principal.name,
            escalates_to="AdministratorAccess",
            explanation=(
                f"{principal.name} can call iam:AddUserToGroup, so it can add itself to a "
                f"group carrying privileged policies and inherit that group's access."
            ),
            exploit_command=(
                f"aws iam add-user-to-group --user-name {principal.name} "
                f"--group-name <privileged-group>"
            ),
            remediation=(
                f"Remove iam:AddUserToGroup from {principal.name}, or restrict it with a "
                f"permissions boundary / condition so it cannot self-join privileged groups."
            ),
        )
