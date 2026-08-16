"""Technique: iam:CreateLoginProfile / iam:UpdateLoginProfile self-escalation.

If a user can set (CreateLoginProfile) or reset (UpdateLoginProfile) the
console password of another, more-privileged user, it can take over that
user's console access. These two permissions are the same technique --
set vs. reset -- so they live in one rule file; the rule emits a finding
for whichever permission the principal holds. Classic Rhino Security Labs
methods; direct edges, no graph needed.

Note (v1 scope): flags the capability, not the existence of a specific
privileged target to take over.
"""

from __future__ import annotations

from ..model import Account, Finding, Principal, principal_can
from .base import Rule, register

# permission -> (aws cli verb, human label)
_VARIANTS = {
    "iam:CreateLoginProfile": ("create-login-profile", "set"),
    "iam:UpdateLoginProfile": ("update-login-profile", "reset"),
}


@register
class LoginProfile(Rule):
    id = "login_profile"
    name = "Set/reset another user's console password (iam:Create/UpdateLoginProfile)"
    severity = "HIGH"

    def check(self, principal: Principal, account: Account) -> Finding | None:
        if principal.ptype != "user":
            return None

        for perm, (verb, action_word) in _VARIANTS.items():
            if principal_can(principal, perm):
                return Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    principal=principal.name,
                    escalates_to="a more-privileged user",
                    explanation=(
                        f"{principal.name} can call {perm}, so it can {action_word} the console "
                        f"password of a more-privileged user and log in as that user."
                    ),
                    exploit_command=(
                        f"aws iam {verb} --user-name <privileged-target-user> "
                        f"--password '<NewPassw0rd!>'"
                    ),
                    remediation=(
                        f"Scope {perm} on {principal.name} to its own user only, or remove it."
                    ),
                )
        return None
