# Example output

These reports were produced by running the tool against one of the bundled
sample accounts — not a real AWS account:

```bash
iam-escalate analyze fixtures/assume_role_chain_account.json --report examples/sample-report.html
```

`sample-report.md` is the same output in Markdown. Both show a two-hop
escalation (a low-privilege user who can assume a role that can make itself
admin) alongside the one-hop path the role has on its own.
