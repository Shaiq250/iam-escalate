"""Run the rule set over an account and collect findings.

M0 does direct (single-hop) escalation only: for each principal, ask
every rule whether it applies. Multi-hop path finding (build a graph,
search principal -> role -> admin) is milestone M4 and will wrap this
same rule output.
"""

from __future__ import annotations

from .model import Account, Finding
from .rules import REGISTRY


def analyze(account: Account) -> list[Finding]:
    findings: list[Finding] = []
    for principal in account.principals:
        for rule in REGISTRY:
            finding = rule.check(principal, account)
            if finding is not None:
                findings.append(finding)
    return findings
