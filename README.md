# iam-escalate

Find **AWS IAM privilege-escalation paths** from a read-only view of an account.
Point it at an account, and it reports which identities can reach admin — and
exactly how.

It's a scanner, in the same spirit as tools like PMapper: a collector pulls the
IAM configuration, an analyzer models the permissions and searches for
escalation paths, and a report shows each path with the exploit steps and the
fix.

## Install

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"        # add ,aws  ->  ".[dev,aws]"  for live collection
```

`analyze` runs on the standard library alone. `boto3` is only needed for live
`collect`.

## Use

```bash
# Offline: analyze the bundled sample account (no AWS needed)
iam-escalate analyze fixtures/sample_account.json

# Write an HTML report
iam-escalate analyze fixtures/sample_account.json --report findings.html

# Live: pull a real account with read-only creds, then analyze the dump
iam-escalate collect --profile myaccount --out account.json
iam-escalate analyze account.json --report findings.html
```

## Scope (v1)

**In:** single AWS account; direct + PassRole/AssumeRole escalation techniques;
wildcard and Allow/Deny handling; Markdown/HTML reports; tests per technique.

**Out (deliberately):** full IAM condition evaluation, permission boundaries,
SCPs/Organizations, cross-account paths, Azure, web UI. Statements carrying
conditions are flagged for manual review rather than evaluated.

## Roadmap

- **M0** scaffolding + one example rule + offline fixtures  ← you are here
- **M1** live boto3 collector (`get_account_authorization_details`)
- **M2** real permission model (attached + group-inherited policies, Deny precedence)
- **M3** the full ~10-technique rule set
- **M4** graph + multi-hop path finding (principal → role → admin)
- **M5** polished reports
- **M6** tests, CI, sample reports

## Legal

Only run this against accounts you own or are explicitly authorized to assess.
