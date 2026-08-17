"""Render escalation paths as Markdown or minimal HTML.

The report is path-centric: each result is a route from a principal to
admin, shown hop by hop, with the exploit command and remediation for
the step that actually reaches admin. Direct escalations are simply
one-hop paths.
"""

from __future__ import annotations

import html

from .graph import ADMIN, EscalationPath
from .model import Finding
from .rules import REGISTRY

# Human labels for the hop techniques (direct-rule labels come from the registry).
_HOP_LABELS = {
    "assume_role": "Assume role (sts:AssumeRole)",
    "pass_role_lambda": "Pass role to a new Lambda (iam:PassRole + lambda:CreateFunction)",
    "pass_role_ec2": "Pass role to a new EC2 instance (iam:PassRole + ec2:RunInstances)",
}


def _labels() -> dict[str, str]:
    labels = dict(_HOP_LABELS)
    for rule in REGISTRY:
        labels[rule.id] = rule.name
    return labels


def _finding_index(direct_findings: list[Finding]) -> dict[tuple[str, str], Finding]:
    return {(f.principal, f.rule_id): f for f in direct_findings}


def _show(node: str) -> str:
    return "admin" if node == ADMIN else node


def _sorted(paths: list[EscalationPath]) -> list[EscalationPath]:
    # longer chains first (more interesting), then alphabetical.
    return sorted(paths, key=lambda p: (-(len(p.nodes)), p.source))


def paths_to_markdown(paths: list[EscalationPath], direct_findings: list[Finding]) -> str:
    if not paths:
        return "# IAM escalation report\n\nNo escalation paths to admin found.\n"

    labels = _labels()
    idx = _finding_index(direct_findings)
    out = ["# IAM escalation report", "",
           f"Found **{len(paths)}** escalation path(s) to admin.", ""]

    for p in _sorted(paths):
        hops = len(p.nodes) - 1
        out.append(f"## [HIGH] {p.source} → admin  ({hops} hop{'s' if hops != 1 else ''})")
        out.append("")

        chain = _show(p.nodes[0])
        for i, techs in enumerate(p.hop_techniques):
            joined = ", ".join(labels.get(t, t) for t in techs)
            chain += f"  --[{joined}]-->  {_show(p.nodes[i + 1])}"
        out += ["```", chain, "```", "", "Steps:"]

        for i, techs in enumerate(p.hop_techniques):
            frm, to = p.nodes[i], p.nodes[i + 1]
            names = ", ".join(labels.get(t, t) for t in techs)
            out.append(f"{i + 1}. `{_show(frm)}` → `{_show(to)}` — {names}")
            if to == ADMIN:
                for t in techs:
                    finding = idx.get((frm, t))
                    if finding:
                        out.append(f"   - Exploit: `{finding.exploit_command}`")
                        out.append(f"   - Fix: {finding.remediation}")
                        break
        out += ["", "---", ""]

    return "\n".join(out)


def paths_to_html(paths: list[EscalationPath], direct_findings: list[Finding]) -> str:
    body = [
        "<meta charset='utf-8'>",
        "<style>body{font:15px system-ui;max-width:820px;margin:2rem auto;padding:0 1rem}"
        "code,pre{background:#f4f4f5;border-radius:4px}pre{padding:.75rem;overflow-x:auto}"
        ".HIGH{color:#b91c1c}hr{border:0;border-top:1px solid #e4e4e7}"
        "li{margin:.2rem 0}</style>",
        "<h1>IAM escalation report</h1>",
    ]
    if not paths:
        body.append("<p>No escalation paths to admin found.</p>")
        return "\n".join(body)

    labels = _labels()
    idx = _finding_index(direct_findings)
    body.append(f"<p>Found <strong>{len(paths)}</strong> escalation path(s) to admin.</p>")

    for p in _sorted(paths):
        hops = len(p.nodes) - 1
        body.append(f"<h2 class='HIGH'>{html.escape(p.source)} &rarr; admin "
                    f"({hops} hop{'s' if hops != 1 else ''})</h2>")

        chain = _show(p.nodes[0])
        for i, techs in enumerate(p.hop_techniques):
            joined = ", ".join(labels.get(t, t) for t in techs)
            chain += f"  --[{joined}]-->  {_show(p.nodes[i + 1])}"
        body.append(f"<pre>{html.escape(chain)}</pre>")

        body.append("<ol>")
        for i, techs in enumerate(p.hop_techniques):
            frm, to = p.nodes[i], p.nodes[i + 1]
            names = ", ".join(labels.get(t, t) for t in techs)
            item = f"<strong>{html.escape(_show(frm))} &rarr; {html.escape(_show(to))}</strong> &mdash; {html.escape(names)}"
            if to == ADMIN:
                for t in techs:
                    finding = idx.get((frm, t))
                    if finding:
                        item += (f"<br><em>Exploit:</em> <code>{html.escape(finding.exploit_command)}</code>"
                                 f"<br><em>Fix:</em> {html.escape(finding.remediation)}")
                        break
            body.append(f"<li>{item}</li>")
        body.append("</ol><hr>")

    return "\n".join(body)
