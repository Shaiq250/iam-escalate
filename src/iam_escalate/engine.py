"""Run the rule set over an account and collect direct findings.

Each rule asks whether a single principal can escalate on its own. This
module exposes that as run_direct_rules(); analyze() is kept as the
stable name for "the list of direct findings". The graph layer (M4,
graph.py) consumes run_direct_rules() to turn direct escalations into
edges toward admin, then searches for multi-hop paths on top.
"""

from __future__ import annotations

from .model import Account, Finding
from .rules import REGISTRY


def run_direct_rules(account: Account) -> list[Finding]:
    """Every direct (single-principal) escalation finding in the account."""
    findings: list[Finding] = []
    for principal in account.principals:
        for rule in REGISTRY:
            finding = rule.check(principal, account)
            if finding is not None:
                findings.append(finding)
    return findings


def analyze(account: Account) -> list[Finding]:
    """Stable alias for the direct-findings list."""
    return run_direct_rules(account)
