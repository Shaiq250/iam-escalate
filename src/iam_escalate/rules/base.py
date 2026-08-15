"""The rule interface.

Every escalation technique is a small, self-contained Rule. Adding a
new technique means adding one file in this folder that subclasses Rule
and gets picked up automatically by the registry. This pluggability is
the design decision that keeps the tool clean as the technique count
grows toward the ~10 in the v1 plan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..model import Account, Finding, Principal


class Rule(ABC):
    id: str          # short stable id, e.g. "attach_user_policy"
    name: str        # human name for reports
    severity: str = "HIGH"

    @abstractmethod
    def check(self, principal: Principal, account: Account) -> Finding | None:
        """Return a Finding if `principal` can escalate via this technique, else None."""
        raise NotImplementedError


# Populated by rules/__init__.py at import time.
REGISTRY: list[Rule] = []


def register(rule_cls: type[Rule]) -> type[Rule]:
    """Class decorator: add a rule to the global registry."""
    REGISTRY.append(rule_cls())
    return rule_cls
