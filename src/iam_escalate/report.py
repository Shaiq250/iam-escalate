"""Render findings as Markdown or a minimal standalone HTML page.

The report is the tool's product, so it stays readable and
copy-pasteable: each finding shows the path, why it works, the exact
CLI to exploit it, and the fix.
"""

from __future__ import annotations

import html

from .model import Finding


def to_markdown(findings: list[Finding]) -> str:
    if not findings:
        return "# IAM escalation report\n\nNo escalation paths found. \n"

    lines = ["# IAM escalation report", "", f"Found **{len(findings)}** escalation path(s).", ""]
    for f in findings:
        lines += [
            f"## [{f.severity}] {f.principal} -> {f.escalates_to}",
            "",
            f"**Technique:** `{f.rule_id}`",
            "",
            f"{f.explanation}",
            "",
            "**Exploit:**",
            "",
            "```bash",
            f.exploit_command,
            "```",
            "",
            f"**Remediation:** {f.remediation}",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)


def to_html(findings: list[Finding]) -> str:
    body = [
        "<meta charset='utf-8'>",
        "<style>body{font:15px system-ui;max-width:760px;margin:2rem auto;padding:0 1rem}"
        "code,pre{background:#f4f4f5;border-radius:4px}pre{padding:.75rem;overflow-x:auto}"
        ".HIGH{color:#b91c1c}.MEDIUM{color:#b45309}.LOW{color:#3f6212}hr{border:0;border-top:1px solid #e4e4e7}</style>",
        "<h1>IAM escalation report</h1>",
    ]
    if not findings:
        body.append("<p>No escalation paths found.</p>")
        return "\n".join(body)

    body.append(f"<p>Found <strong>{len(findings)}</strong> escalation path(s).</p>")
    for f in findings:
        body += [
            f"<h2 class='{f.severity}'>[{f.severity}] {html.escape(f.principal)} "
            f"&rarr; {html.escape(f.escalates_to)}</h2>",
            f"<p><em>Technique:</em> <code>{html.escape(f.rule_id)}</code></p>",
            f"<p>{html.escape(f.explanation)}</p>",
            f"<p><strong>Exploit:</strong></p><pre>{html.escape(f.exploit_command)}</pre>",
            f"<p><strong>Remediation:</strong> {html.escape(f.remediation)}</p>",
            "<hr>",
        ]
    return "\n".join(body)
