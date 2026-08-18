"""Technique: grant admin to a role via a policy write.

If a principal can write policies onto a role (iam:PutRolePolicy for an
inline policy, or iam:AttachRolePolicy for a managed one), it can give
that role administrator permissions and then operate as the role. Both
are classic Rhino Security Labs methods. Two permissions, one technique,
so they share a rule file (the rule fires on whichever is held).
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register

# permission -> (cli verb + args template, human action word)
_VARIANTS = {
    "iam:PutRolePolicy": (
        "put-role-policy --role-name <role> --policy-name esc "
        "--policy-document '{\"Version\":\"2012-10-17\",\"Statement\":"
        "[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'",
        "write an inline admin policy onto",
    ),
    "iam:AttachRolePolicy": (
        "attach-role-policy --role-name <role> "
        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "attach the admin policy to",
    ),
}


@register
class ModifyRolePolicy(Rule):
    id = "modify_role_policy"
    name = "Grant admin to a role via policy write (iam:PutRolePolicy / iam:AttachRolePolicy)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        for perm, (cli, action_word) in _VARIANTS.items():
            if principal_can(principal, perm):
                return Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    principal=principal.name,
                    escalates_to="AdministratorAccess (via a role)",
                    explanation=(
                        f"{principal.name} can call {perm}, so it can {action_word} a role "
                        f"and then operate as that role with full admin."
                    ),
                    exploit_command=f"aws iam {cli}",
                    remediation=(
                        f"Remove {perm} from {principal.name}, or restrict it with a "
                        f"permissions boundary / condition so it cannot grant roles admin."
                    ),
                )
        return None
