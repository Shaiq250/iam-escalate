"""Technique: grant admin to a group via a policy write.

If a principal can write policies onto a group (iam:PutGroupPolicy for an
inline policy, or iam:AttachGroupPolicy for a managed one), it can give
that group administrator permissions, which every member inherits -- so
it escalates itself (if a member) or anyone it can add to the group.
Classic Rhino Security Labs methods; two permissions, one technique.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register

_VARIANTS = {
    "iam:PutGroupPolicy": (
        "put-group-policy --group-name <group> --policy-name esc "
        "--policy-document '{\"Version\":\"2012-10-17\",\"Statement\":"
        "[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}'",
        "write an inline admin policy onto",
    ),
    "iam:AttachGroupPolicy": (
        "attach-group-policy --group-name <group> "
        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
        "attach the admin policy to",
    ),
}


@register
class ModifyGroupPolicy(Rule):
    id = "modify_group_policy"
    name = "Grant admin to a group via policy write (iam:PutGroupPolicy / iam:AttachGroupPolicy)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        for perm, (cli, action_word) in _VARIANTS.items():
            if principal_can(principal, perm):
                return Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    principal=principal.name,
                    escalates_to="AdministratorAccess (via a group)",
                    explanation=(
                        f"{principal.name} can call {perm}, so it can {action_word} a group "
                        f"whose members then inherit full admin."
                    ),
                    exploit_command=f"aws iam {cli}",
                    remediation=(
                        f"Remove {perm} from {principal.name}, or restrict it with a "
                        f"permissions boundary / condition so it cannot grant groups admin."
                    ),
                )
        return None
