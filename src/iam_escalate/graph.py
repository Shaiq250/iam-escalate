"""Escalation graph and path search (M4).

Turns the rule engine's results into a directed graph of "who can
escalate to whom", then searches for routes to admin.

  - Nodes are principals (users/roles) plus one sentinel ADMIN node.
  - Direct rules produce edges straight to ADMIN: "this principal can
    make itself admin". Several techniques may enable the same hop, so
    an edge carries a list of techniques.
  - Hop-based rules (AssumeRole, PassRole; added next) will produce
    edges between ordinary principals, so escalation becomes a path of
    length > 1.

A principal "can reach admin" exactly when a directed path exists from
its node to ADMIN. With only direct edges every such path is length 1,
so this currently mirrors the direct findings -- which is the proof that
the graph layer is wired up correctly before hops are added.
"""

from __future__ import annotations

from dataclasses import dataclass

import networkx as nx

from .engine import run_direct_rules
from .model import Account

ADMIN = "*admin*"  # sentinel node representing admin-equivalent access


@dataclass
class EscalationPath:
    """A route from one principal to admin."""

    source: str
    nodes: list[str]                 # ordered node names, last is ADMIN
    hop_techniques: list[list[str]]  # technique ids enabling each hop


def build_graph(account: Account) -> nx.DiGraph:
    """Build the escalation graph for an account."""
    graph = nx.DiGraph()
    graph.add_node(ADMIN)
    for principal in account.principals:
        graph.add_node(principal.name)

    # Direct escalations become edges principal -> ADMIN. Multiple
    # techniques for the same principal aggregate onto the one edge.
    for finding in run_direct_rules(account):
        if graph.has_edge(finding.principal, ADMIN):
            graph[finding.principal][ADMIN]["techniques"].append(finding.rule_id)
        else:
            graph.add_edge(finding.principal, ADMIN, techniques=[finding.rule_id])

    return graph


def find_paths(account: Account) -> list[EscalationPath]:
    """Every principal that can reach admin, with the route it takes."""
    graph = build_graph(account)
    paths: list[EscalationPath] = []

    for node in graph.nodes:
        if node == ADMIN:
            continue
        if not nx.has_path(graph, node, ADMIN):
            continue
        node_path = nx.shortest_path(graph, node, ADMIN)
        hop_techniques = [
            graph[a][b].get("techniques", []) for a, b in zip(node_path, node_path[1:])
        ]
        paths.append(
            EscalationPath(source=node, nodes=node_path, hop_techniques=hop_techniques)
        )

    return paths
