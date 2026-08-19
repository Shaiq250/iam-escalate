# Roadmap

The tool covers the escalation techniques that show up most often, plus the
permission model behind them: effective permissions across inline, managed, and
group policies, explicit deny, permission boundaries, the `iam:PassedToService`
condition, resource-scoped role hops, and cross-principal chains where one
identity takes over another by assuming it, rewriting its trust, passing it to
compute, taking over its credentials, or joining a group. This is the list of
what's next, roughly in the order I'd tackle it.

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
- Instance-profile chains (`iam:CreateInstanceProfile` plus
  `iam:AddRoleToInstanceProfile` plus `ec2:RunInstances`).

## Model improvements

These change how accurately the existing techniques are judged, not which
techniques exist:

- Resource scoping for the direct self-escalation rules. The hops between
  identities already honour the resource, but the direct rules (attaching or
  writing a policy on yourself, publishing a policy version) still match by
  action alone. The cleanest form also covers the last cross-principal case,
  where a principal grants admin to an identity that was not already dangerous
  and then takes it over. The tool already catches these as chains when the
  target can escalate on its own, so this is a precision improvement rather than
  a gap in coverage, and it carries a real risk of trading over-reporting for
  missed paths, so it deserves care.
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
