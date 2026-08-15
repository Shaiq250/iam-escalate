"""Core data types and a minimal IAM-action matcher.

M0 keeps this deliberately simple. The real permission engine (merging
attached + group-inherited policies, handling Deny precedence and
conditions) arrives in milestone M2. What's here is enough to run the
whole pipeline end-to-end against a fixture.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Principal:
    """A user, role, or group, reduced to the actions it is allowed."""

    name: str
    arn: str
    ptype: str  # "user" | "role" | "group"
    allowed_actions: set[str] = field(default_factory=set)
    has_conditions: bool = False  # flagged for manual review; ignored in M0


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


def action_matches(granted: str, needed: str) -> bool:
    """Does an IAM action string `granted` cover the action `needed`?

    Handles the two wildcard cases that matter most:
      "*"        -> matches anything
      "iam:*"    -> matches any action in the iam service
      "iam:Get*" -> prefix match within a service
    Comparison is case-insensitive, as IAM treats actions.
    """
    granted = granted.lower()
    needed = needed.lower()
    if granted == "*":
        return True
    if granted.endswith("*"):
        return needed.startswith(granted[:-1])
    return granted == needed


def principal_can(principal: Principal, needed: str) -> bool:
    """True if any of the principal's allowed actions covers `needed`."""
    return any(action_matches(a, needed) for a in principal.allowed_actions)
