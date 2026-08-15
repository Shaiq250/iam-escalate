"""Core data types and the IAM-action matcher.

A principal's real permissions are its *effective* permissions: every
action it is allowed, minus every action explicitly denied. In IAM an
explicit Deny always wins over any Allow, so `principal_can` subtracts
denies at the end.

Simplifications still in place (deliberate, documented):
  - resources are not modelled — an action is treated as allowed/denied
    regardless of which resource the statement targets
  - conditions are not evaluated — `has_conditions` flags a principal
    for manual review instead
  - an attached managed policy whose document isn't in the dump is
    recorded in `unresolved_policies` rather than silently ignored
These are revisited in later milestones.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Principal:
    """A user, role, or group, reduced to what it can and cannot do."""

    name: str
    arn: str
    ptype: str  # "user" | "role" | "group"
    allowed_actions: set[str] = field(default_factory=set)
    denied_actions: set[str] = field(default_factory=set)
    has_conditions: bool = False  # flagged for manual review; not evaluated
    unresolved_policies: list[str] = field(default_factory=list)  # attached but doc not in dump


@dataclass
class Account:
    """The whole account, parsed from a GetAccountAuthorizationDetails-shaped file."""

    principals: list[Principal] = field(default_factory=list)


@dataclass
class Finding:
    """One escalation path discovered by a rule."""

    rule_id: str
    severity: str  # "HIGH" | "MEDIUM" | "LOW"
    principal: str
    escalates_to: str
    explanation: str
    exploit_command: str
    remediation: str


def action_matches(pattern: str, needed: str) -> bool:
    """Does an IAM action `pattern` cover the action `needed`?

    Handles the wildcard cases that matter most:
      "*"        -> matches anything
      "iam:*"    -> matches any action in the iam service
      "iam:Get*" -> prefix match within a service
    Comparison is case-insensitive, as IAM treats actions.
    """
    pattern = pattern.lower()
    needed = needed.lower()
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return needed.startswith(pattern[:-1])
    return pattern == needed


def principal_can(principal: Principal, needed: str) -> bool:
    """True if the principal can perform `needed` — allowed AND not denied.

    An explicit Deny overrides any Allow, so a matching deny short-circuits
    to False even when an allow also matches.
    """
    if any(action_matches(d, needed) for d in principal.denied_actions):
        return False
    return any(action_matches(a, needed) for a in principal.allowed_actions)
