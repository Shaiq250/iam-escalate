"""Core data types and the IAM permission matcher.

A principal's permissions are stored as GRANTS: each grant pairs a set of
actions with the set of resources those actions apply to (mirroring one
IAM statement). Keeping actions and resources paired per grant is what
lets the tool ask resource-scoped questions -- "can this principal do
ACTION on this specific RESOURCE?" -- instead of assuming every grant is
on "*".

`principal_can(principal, action, resource=None)`:
  - resource=None  -> "does the principal hold this action on ANY
    resource?" (an explicit Deny of the action anywhere blocks it). This
    is what the direct self-escalation rules use.
  - resource=<arn> -> "can the principal do this action on that exact
    target?" Both action and resource must match, and a Deny matching
    both blocks it. This is what the role-hop checks use.

Convenience: `allowed_actions` / `denied_actions` may be passed when
constructing a Principal (handy in tests); they are folded into grants
on "*". Real analysis works off the grant lists.

Simplifications still in place (deliberate, documented):
  - conditions are not evaluated -- `has_conditions` flags a principal
    for manual review instead
  - an attached managed policy whose document isn't in the dump is
    recorded in `unresolved_policies` rather than silently ignored
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Grant:
    """One statement's actions paired with the resources they apply to."""

    actions: frozenset[str]
    resources: frozenset[str]


@dataclass
class Principal:
    """A user, role, or group, reduced to what it can and cannot do."""

    name: str
    arn: str
    ptype: str  # "user" | "role" | "group"
    allowed_actions: set[str] = field(default_factory=set)  # convenience -> folded to a grant on "*"
    denied_actions: set[str] = field(default_factory=set)   # convenience -> folded to a deny on "*"
    allow: list[Grant] = field(default_factory=list)
    deny: list[Grant] = field(default_factory=list)
    has_conditions: bool = False  # flagged for manual review; not evaluated
    unresolved_policies: list[str] = field(default_factory=list)  # attached but doc not in dump
    trust_principals: set[str] = field(default_factory=set)  # who may assume this role (roles only)

    def __post_init__(self) -> None:
        # Fold the convenience action-only sets into grants on any resource.
        if self.allowed_actions:
            self.allow.append(Grant(frozenset(self.allowed_actions), frozenset({"*"})))
        if self.denied_actions:
            self.deny.append(Grant(frozenset(self.denied_actions), frozenset({"*"})))


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


def resource_matches(pattern: str, target: str) -> bool:
    """Does a resource `pattern` (ARN, possibly wildcarded) cover `target`?

    IAM resource wildcards: "*" matches any run of characters, "?" matches
    exactly one. Matching is case-sensitive (ARNs are).
    """
    if pattern == "*":
        return True
    regex = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(regex, target) is not None


def principal_can(principal: Principal, action: str, resource: str | None = None) -> bool:
    """True if the principal can perform `action` (optionally on `resource`).

    An explicit Deny that matches wins over any Allow. When `resource` is
    None the check is action-only (deny of the action anywhere blocks it);
    when a resource is given, both action and resource must match.
    """

    def grant_matches(g: Grant) -> bool:
        if not any(action_matches(a, action) for a in g.actions):
            return False
        if resource is None:
            return True
        return any(resource_matches(r, resource) for r in g.resources)

    if any(grant_matches(g) for g in principal.deny):
        return False
    return any(grant_matches(g) for g in principal.allow)
