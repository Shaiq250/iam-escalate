# iam-escalate

Finds privilege-escalation paths in an AWS account's IAM setup. You point it at
an account, and it tells you which users and roles can reach administrator
access, and the exact sequence of steps they'd use to get there.

It works from a read-only view of IAM, so it never changes anything. The
analysis runs offline against a saved copy of the account, which means you can
develop against the bundled sample data without an AWS account at all.

The report is where it tries to be useful. Every path comes with the command an
attacker would run and the change that closes it.

## What it finds

A path can be a single step or a chain of them.

The simple case is a user who can escalate itself directly, for example someone
holding `iam:AttachUserPolicy`, who can attach the AWS `AdministratorAccess`
policy to their own account.

The more interesting case is a chain, where no single identity looks dangerous
on its own:

```
low-larry  --[Assume role (sts:AssumeRole)]-->  admin-role  --[iam:AttachUserPolicy]-->  admin
```

Here `low-larry` has no dangerous permission of their own. They can only assume
`admin-role`, and it's that role that can make itself admin. Neither half is a
finding by itself. The escalation only exists as the path.

Techniques currently covered:

Direct self-escalation covers attaching or writing a policy on yourself
(`iam:AttachUserPolicy`, `iam:PutUserPolicy`), publishing a new version of a
policy you already use (`iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`),
adding yourself to a group (`iam:AddUserToGroup`), minting new credentials for a
user (`iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`),
and granting admin to a role or group you can use (`iam:PutRolePolicy`,
`iam:AttachRolePolicy`, `iam:PutGroupPolicy`, `iam:AttachGroupPolicy`).

Role hops cover `sts:AssumeRole` (assuming a role whose trust policy allows you),
and `iam:PassRole` paired with a service that runs your code (Lambda, EC2, Glue,
CloudFormation, Data Pipeline, ECS, CodeBuild, or SageMaker), which hands a
powerful role to compute you control.

See ROADMAP.md for what isn't covered yet.

## Install

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -e ".[aws,dev]"
```

The core install pulls in `networkx`, which is used for the path search. The
`aws` extra adds `boto3`, which is only needed to pull a live account, and the
`dev` extra adds `pytest`.

## Use

The tool has two steps. `collect` pulls IAM data out of an account into a JSON
file, and `analyze` reads that file and reports the paths. They're separate on
purpose. You can collect once with read-only credentials and then analyze the
file offline as many times as you like.

```bash
# Analyze the bundled sample data (no AWS needed)
iam-escalate analyze fixtures/assume_role_chain_account.json

# Pull a real account, then analyze it
iam-escalate collect --profile myprofile --out account.json
iam-escalate analyze account.json

# Write an HTML report instead of printing to the terminal
iam-escalate analyze account.json --report report.html
```

`analyze` exits with status 1 when it finds any path to admin and 0 when it
doesn't, so it drops into a CI pipeline the same way a failing test would.

Live collection needs read access to IAM. The AWS-managed `IAMReadOnlyAccess`
policy is enough, and it can't change anything.

## How it works

`collect` calls `iam:GetAccountAuthorizationDetails`, which returns every user,
role, group, and policy in one response, and writes it to a file.

`analyze` then works out each principal's effective permissions. It merges the
principal's inline policies, its attached managed policies (resolved from the
same dump), and anything inherited from its groups. Then it subtracts anything
explicitly denied, because in IAM an explicit Deny always wins. If the principal
has a permission boundary, its access is capped to what the boundary allows too.

From there it builds a directed graph. A principal that can escalate directly
gets an edge to an "admin" node. A principal that can assume or pass a role to
another identity gets an edge to that identity. Finding an escalation is then
just searching for a path to the admin node, and the path is the attack chain.

## Scope and limitations

The tool makes some deliberate simplifications. They're listed here because a
security tool that hides what it skipped is worse than useless.

- Resource scoping applies to the role hops but not yet to the direct
  techniques. When a principal can `iam:PassRole` or `sts:AssumeRole` only on
  specific role ARNs, the tool respects that and won't draw an edge to a role
  outside the scope. The direct self-escalation techniques are still matched by
  action alone, without checking the resource.
- Conditions are only partly evaluated. The tool honours `iam:PassedToService`,
  which limits `iam:PassRole` to named services, so a role that may only be
  passed to Lambda does not produce edges for the other services. Any other
  condition cannot be resolved without the live request context, so the
  statement is counted as if the condition were met and the principal is listed
  under "Not fully evaluated" for you to check by hand.
- It reads permission boundaries and caps a principal's access to the
  intersection of its policies and the boundary, so an admin-looking policy
  sitting behind a restrictive boundary is not reported as a path. It does not
  yet read SCPs or Organizations policies, which can also restrict access.
- It's single-account only. Cross-account trust and escalation aren't modelled.
- Direct techniques are applied to roles as well as users. A role holding, say,
  `iam:AttachUserPolicy` is flagged as able to reach admin, even though turning
  that into the role's own access can take a further step. For a tool meant to
  surface things for review, over-reporting here is the safer default.
- A managed policy or permission boundary whose document isn't in the dump is
  listed under "Not fully evaluated" rather than guessed at.

None of these are hard to add later. The design keeps each one isolated. See
ROADMAP.md.

## Tests

```bash
pytest -q
```

Every technique and the path search have tests, and they run on every push via
GitHub Actions.

## Legal

Only run this against an account you own or have written permission to assess.
