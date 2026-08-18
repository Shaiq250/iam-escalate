# Roadmap

The tool covers the escalation techniques that show up most often, plus the
permission model behind them: effective permissions across inline, managed, and
group policies, explicit deny, resource-scoped role hops, permission boundaries,
and the `iam:PassedToService` condition. This is the list of what's next,
roughly in the order I'd tackle it.

Adding a technique is deliberately small: each one is a single file in
`src/iam_escalate/rules/` (for direct self-escalation) or a generator in
`src/iam_escalate/hops.py` (for anything that hops between identities), plus a
test. Nothing else has to change.

## More techniques

The Rhino Security Labs catalogue lists around 21 escalation methods. The tool
implements a good part of them. Still to add:

- `lambda:UpdateFunctionCode` on a function that already runs a privileged role.
  Overwrite the code, get that role's permissions. This one needs the collector
  to pull Lambda functions and their roles, which is a data source beyond the
  IAM dump.
- Modifying an existing role's trust policy (`iam:UpdateAssumeRolePolicy`) to add
  yourself to it, then assuming it.
- Instance-profile chains (`iam:CreateInstanceProfile` plus
  `iam:AddRoleToInstanceProfile` plus `ec2:RunInstances`).

## Model improvements

These change how accurately the existing techniques are judged, not which
techniques exist:

- Resource scoping for the direct techniques. The role hops already honour the
  resource, but the direct self-escalation rules still match by action alone.
  Doing this properly means modelling escalation across principals, where one
  identity can modify another and then act as it, so it is closer to a new
  capability than a small change.
- SCPs and Organizations policies, which can cap effective access below what the
  identity policies and permission boundary grant.
- General condition evaluation beyond `iam:PassedToService`. Most conditions
  depend on the live request (source IP, MFA, time, region) and cannot be
  resolved statically, so these will likely stay flagged rather than evaluated.
- Cross-account paths, following `AssumeRole` trust into other accounts.
- A live fallback (`iam:GetPolicy` and `iam:GetPolicyVersion`) for the rare
  managed policy or boundary whose document isn't in the account dump.

## Beyond AWS

- Azure and Entra ID support, as a separate collector feeding the same graph.
