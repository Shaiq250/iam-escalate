# Roadmap

v1 covers the escalation techniques that show up most often and the core
permission model behind them. This is the list of what's next, roughly in the
order I'd tackle it.

Adding a technique is deliberately small: each one is a single file in
`src/iam_escalate/rules/` (for direct self-escalation) or a generator in
`src/iam_escalate/hops.py` (for anything that hops between identities), plus a
test. Nothing else has to change.

## More techniques

The Rhino Security Labs catalogue lists around 21 escalation methods. v1
implements a subset. Still to add:

- `iam:PassRole` through more services — Glue development endpoints,
  CloudFormation, Data Pipeline, ECS tasks, SageMaker, CodeBuild. Each is the
  same idea as the Lambda and EC2 cases already covered, with a different
  service action.
- `lambda:UpdateFunctionCode` on a function that already runs a privileged
  role — overwrite the code, get that role's permissions.
- Modifying an existing role's trust policy (`iam:UpdateAssumeRolePolicy`) to
  add yourself to it, then assuming it.
- Role- and group-targeted versions of the policy-write techniques
  (`iam:PutRolePolicy`, `iam:AttachRolePolicy`, `iam:PutGroupPolicy`,
  `iam:AttachGroupPolicy`).
- Instance-profile chains (`iam:CreateInstanceProfile` +
  `iam:AddRoleToInstanceProfile` + `ec2:RunInstances`).

## Model improvements

These change how accurately the existing techniques are judged, not which
techniques exist:

- Resource scoping. Right now permissions are matched by action only, so a
  permission scoped to specific resources is treated as if it applied to all of
  them. Honouring the resource would cut down over-reporting on `PassRole` and
  `AssumeRole` especially.
- Condition evaluation. Statements with conditions are currently flagged for
  manual review. A first pass could handle the common cases.
- Permission boundaries and SCPs, which can cap effective access below what the
  identity policies grant.
- Cross-account paths — following `AssumeRole` trust into other accounts.
- A live fallback (`iam:GetPolicy` / `iam:GetPolicyVersion`) for the rare
  managed policy whose document isn't in the account dump.

## Beyond AWS

- Azure / Entra ID support, as a separate collector feeding the same graph.
