"""Render escalation paths as Markdown or minimal HTML.

The report is path-centric: each result is a route from a principal to
admin, shown hop by hop, with the exploit command and remediation for
the step that actually reaches admin. Direct escalations are one-hop
paths.

The report is also honest about its own blind spots: a "Not fully
evaluated" section lists principals whose analysis was incomplete --
an attached managed policy whose document wasn't in the dump, or a
policy carrying a Condition the tool doesn't evaluate -- so a reader
never mistakes "no paths found" for "definitely safe".
"""

from __future__ import annotations

import html

from .graph import ADMIN, EscalationPath
from .model import Account, Finding
from .rules import REGISTRY

# Human labels for the hop techniques (direct-rule labels come from the registry).
_HOP_LABELS = {
    "assume_role": "Assume role (sts:AssumeRole)",
    "update_trust_policy": "Rewrite the role's trust policy and assume it (iam:UpdateAssumeRolePolicy + sts:AssumeRole)",
    "impersonate_user": "Take over another user's credentials (iam:CreateAccessKey / iam:CreateLoginProfile / iam:UpdateLoginProfile)",
    "pass_role_lambda": "Pass role to a new Lambda (iam:PassRole + lambda:CreateFunction)",
    "pass_role_ec2": "Pass role to a new EC2 instance (iam:PassRole + ec2:RunInstances)",
    "pass_role_glue": "Pass role to a Glue dev endpoint (iam:PassRole + glue:CreateDevEndpoint)",
    "pass_role_cloudformation": "Pass role to a CloudFormation stack (iam:PassRole + cloudformation:CreateStack)",
    "pass_role_datapipeline": "Pass role to a Data Pipeline (iam:PassRole + datapipeline:CreatePipeline)",
    "pass_role_ecs": "Pass role to an ECS task (iam:PassRole + ecs:RunTask)",
    "pass_role_codebuild": "Pass role to a CodeBuild project (iam:PassRole + codebuild:CreateProject)",
    "pass_role_sagemaker": "Pass role to a SageMaker notebook (iam:PassRole + sagemaker:CreateNotebookInstance)",
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
    return sorted(paths, key=lambda p: (-(len(p.nodes)), p.source))


def _caveats(account: Account | None) -> list[tuple[str, str]]:
    """(principal_name, reason) for anything the analysis couldn't fully cover."""
    if account is None:
        return []
    rows: list[tuple[str, str]] = []
    for p in account.principals:
        if p.unresolved_policies:
            rows.append((p.name, "attached policy not evaluated: "
                                 + ", ".join(p.unresolved_policies)))
        if p.has_conditions:
            rows.append((p.name, "has condition-gated statements (not evaluated)"))
    return sorted(rows)


def paths_to_markdown(
    paths: list[EscalationPath],
    direct_findings: list[Finding],
    account: Account | None = None,
) -> str:
    labels = _labels()
    idx = _finding_index(direct_findings)
    out = ["# IAM escalation report", ""]

    if paths:
        out.append(f"Found **{len(paths)}** escalation path(s) to admin.")
        out.append("")
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
    else:
        out.append("No escalation paths to admin found.")
        out.append("")

    caveats = _caveats(account)
    if caveats:
        out += ["## Not fully evaluated", "",
                "The tool could not fully assess these principals — review them by hand:", ""]
        for name, reason in caveats:
            out.append(f"- `{name}` — {reason}")
        out.append("")

    return "\n".join(out)


def paths_to_html(
    paths: list[EscalationPath],
    direct_findings: list[Finding],
    account: Account | None = None,
) -> str:
    body = [
        "<meta charset='utf-8'>",
        "<style>body{font:15px system-ui;max-width:820px;margin:2rem auto;padding:0 1rem}"
        "code,pre{background:#f4f4f5;border-radius:4px}pre{padding:.75rem;overflow-x:auto}"
        ".HIGH{color:#b91c1c}hr{border:0;border-top:1px solid #e4e4e7}li{margin:.2rem 0}"
        ".caveat{color:#92400e}</style>",
        "<h1>IAM escalation report</h1>",
    ]

    labels = _labels()
    idx = _finding_index(direct_findings)

    if paths:
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
                item = (f"<strong>{html.escape(_show(frm))} &rarr; {html.escape(_show(to))}</strong>"
                        f" &mdash; {html.escape(names)}")
                if to == ADMIN:
                    for t in techs:
                        finding = idx.get((frm, t))
                        if finding:
                            item += (f"<br><em>Exploit:</em> <code>{html.escape(finding.exploit_command)}</code>"
                                     f"<br><em>Fix:</em> {html.escape(finding.remediation)}")
                            break
                body.append(f"<li>{item}</li>")
            body.append("</ol><hr>")
    else:
        body.append("<p>No escalation paths to admin found.</p>")

    caveats = _caveats(account)
    if caveats:
        body.append("<h2 class='caveat'>Not fully evaluated</h2>")
        body.append("<p>The tool could not fully assess these principals — review them by hand:</p>")
        body.append("<ul>")
        for name, reason in caveats:
            body.append(f"<li class='caveat'><code>{html.escape(name)}</code> &mdash; {html.escape(reason)}</li>")
        body.append("</ul>")

    return "\n".join(body)
