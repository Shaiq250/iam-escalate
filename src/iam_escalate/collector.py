"""Turn AWS IAM data into our model.

Two entry points:
  load_account_from_file(path)  -> parse a saved JSON dump (no AWS, no deps)
  collect_from_aws(profile)     -> pull live data via boto3 (boto3 optional)

Permissions are captured as Grants (actions paired with the resources
they apply to) from all three sources -- inline policies, attached
managed policies (resolved from the dump), and group-inherited policies --
with Deny kept separate. Roles also capture their trust policy (who may
assume them) for the graph's AssumeRole edges. A managed policy whose
document isn't in the dump is recorded in unresolved_policies.
"""

from __future__ import annotations

import json

from .model import Account, Grant, Principal, action_matches


def _passed_to_services(condition: dict) -> frozenset[str] | None:
    """Extract iam:PassedToService values from a Condition. None if absent."""
    services: set[str] = set()
    found = False
    for _op, kv in condition.items():
        if not isinstance(kv, dict):
            continue
        for key, val in kv.items():
            if key.lower() == "iam:passedtoservice":
                found = True
                for v in ([val] if isinstance(val, str) else val):
                    services.add(v)
    return frozenset(services) if found else None


def _has_other_conditions(condition: dict) -> bool:
    """True if the Condition has any key other than iam:PassedToService.

    Those are the conditions the tool doesn't evaluate, so they still get
    the principal flagged for manual review.
    """
    for _op, kv in condition.items():
        if not isinstance(kv, dict):
            return True
        for key in kv:
            if key.lower() != "iam:passedtoservice":
                return True
    return False


def _grants_from_policy_doc(doc: dict) -> tuple[list[Grant], list[Grant], bool]:
    """Return (allow_grants, deny_grants, has_conditions) from one document.

    Each statement becomes one Grant pairing its actions with its
    resources. iam:PassedToService is captured onto the grant; any other
    condition sets has_conditions for manual-review flagging.
    """
    allow: list[Grant] = []
    deny: list[Grant] = []
    has_conditions = False
    for stmt in doc.get("Statement", []):
        condition = stmt.get("Condition") or {}
        if _has_other_conditions(condition):
            has_conditions = True
        effect = stmt.get("Effect")
        if effect not in ("Allow", "Deny"):
            continue
        raw_actions = stmt.get("Action", [])
        actions = [raw_actions] if isinstance(raw_actions, str) else raw_actions
        raw_resources = stmt.get("Resource", "*")
        resources = [raw_resources] if isinstance(raw_resources, str) else raw_resources
        grant = Grant(
            frozenset(actions),
            frozenset(resources or ["*"]),
            passed_to_services=_passed_to_services(condition),
        )
        (allow if effect == "Allow" else deny).append(grant)
    return allow, deny, has_conditions


def _trust_principals_from_doc(doc: dict) -> set[str]:
    """Extract the AWS principals a role's trust policy lets assume it."""
    trusted: set[str] = set()
    for stmt in doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        actions = [raw] if isinstance(raw, str) else raw
        if not any(action_matches(a, "sts:AssumeRole") for a in actions):
            continue
        principal = stmt.get("Principal", {})
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        if aws is None:
            continue
        for arn in [aws] if isinstance(aws, str) else aws:
            trusted.add(arn)
    return trusted


def _default_version_document(policy: dict) -> dict | None:
    """Pull the active policy document out of a Policies-list entry."""
    versions = policy.get("PolicyVersionList", [])
    for v in versions:
        if v.get("IsDefaultVersion"):
            return v.get("Document")
    default_id = policy.get("DefaultVersionId")
    for v in versions:
        if v.get("VersionId") == default_id:
            return v.get("Document")
    return versions[0].get("Document") if versions else None


def _build_policy_index(policies: list) -> dict[str, dict]:
    """Map each managed policy ARN -> its active policy document."""
    index: dict[str, dict] = {}
    for pol in policies:
        arn = pol.get("Arn")
        doc = _default_version_document(pol)
        if arn and doc is not None:
            index[arn] = doc
    return index


def _extract_from_policies(
    inline_policies: list,
    attached_managed: list,
    policy_index: dict[str, dict],
) -> tuple[list[Grant], list[Grant], bool, list[str]]:
    """Fold one set of inline + attached-managed policies into grants."""
    allow: list[Grant] = []
    deny: list[Grant] = []
    has_conditions = False
    unresolved: list[str] = []

    for inline in inline_policies:
        a, d, c = _grants_from_policy_doc(inline.get("PolicyDocument", {}))
        allow += a
        deny += d
        has_conditions = has_conditions or c

    for att in attached_managed:
        parn = att.get("PolicyArn")
        doc = policy_index.get(parn)
        if doc is None:
            unresolved.append(att.get("PolicyName") or parn or "<unknown>")
            continue
        a, d, c = _grants_from_policy_doc(doc)
        allow += a
        deny += d
        has_conditions = has_conditions or c

    return allow, deny, has_conditions, unresolved


def _build_group_index(
    groups: list, policy_index: dict[str, dict]
) -> dict[str, tuple[list[Grant], list[Grant], bool, list[str]]]:
    """Resolve each group's policies once, keyed by group name."""
    index: dict[str, tuple[list[Grant], list[Grant], bool, list[str]]] = {}
    for g in groups:
        index[g["GroupName"]] = _extract_from_policies(
            g.get("GroupPolicyList", []),
            g.get("AttachedManagedPolicies", []),
            policy_index,
        )
    return index


def _resolve_boundary(entity: dict, policy_index: dict[str, dict], unresolved: list[str]):
    """Return (boundary_allow, boundary_deny) for an entity's permission boundary.

    None boundary_allow means the entity has no boundary (no cap). If the
    boundary policy's document isn't in the dump, it's flagged in
    `unresolved` and treated as no cap (conservative -- we over-report
    rather than hide a path behind a boundary we couldn't read).
    """
    pb = entity.get("PermissionsBoundary")
    if not pb:
        return None, []
    arn = pb.get("PermissionsBoundaryArn")
    doc = policy_index.get(arn) if arn else None
    if doc is None:
        if arn:
            unresolved.append(arn.rsplit("/", 1)[-1] + " (permission boundary)")
        return None, []
    b_allow, b_deny, _cond = _grants_from_policy_doc(doc)
    return b_allow, b_deny


def _user_principal(user: dict, policy_index, group_index) -> Principal:
    """Build a user Principal from its own policies plus inherited group policies."""
    allow, deny, has_conditions, unresolved = _extract_from_policies(
        user.get("UserPolicyList", []),
        user.get("AttachedManagedPolicies", []),
        policy_index,
    )

    for gname in user.get("GroupList", []):
        g = group_index.get(gname)
        if g is None:
            continue
        g_allow, g_deny, g_cond, g_unresolved = g
        allow += g_allow
        deny += g_deny
        has_conditions = has_conditions or g_cond
        unresolved.extend(g_unresolved)

    unresolved = list(dict.fromkeys(unresolved))
    b_allow, b_deny = _resolve_boundary(user, policy_index, unresolved)

    return Principal(
        name=user["UserName"],
        arn=user["Arn"],
        ptype="user",
        allow=allow,
        deny=deny,
        boundary_allow=b_allow,
        boundary_deny=b_deny,
        has_conditions=has_conditions,
        unresolved_policies=unresolved,
    )


def load_account_from_file(path: str) -> Account:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    policy_index = _build_policy_index(data.get("Policies", []))
    group_index = _build_group_index(data.get("GroupDetailList", []), policy_index)
    principals: list[Principal] = []

    for user in data.get("UserDetailList", []):
        principals.append(_user_principal(user, policy_index, group_index))

    for role in data.get("RoleDetailList", []):
        allow, deny, has_conditions, unresolved = _extract_from_policies(
            role.get("RolePolicyList", []),
            role.get("AttachedManagedPolicies", []),
            policy_index,
        )
        b_allow, b_deny = _resolve_boundary(role, policy_index, unresolved)
        principals.append(
            Principal(
                name=role["RoleName"],
                arn=role["Arn"],
                ptype="role",
                allow=allow,
                deny=deny,
                boundary_allow=b_allow,
                boundary_deny=b_deny,
                has_conditions=has_conditions,
                unresolved_policies=unresolved,
                trust_principals=_trust_principals_from_doc(
                    role.get("AssumeRolePolicyDocument", {})
                ),
            )
        )

    # Groups become principals too, so the graph can treat "add yourself to
    # this group" as an edge into a node whose own policies may reach admin.
    for group in data.get("GroupDetailList", []):
        g_allow, g_deny, g_cond, g_unresolved = group_index.get(
            group["GroupName"], ([], [], False, [])
        )
        principals.append(
            Principal(
                name=group["GroupName"],
                arn=group.get("Arn", f"arn:aws:iam::group/{group['GroupName']}"),
                ptype="group",
                allow=list(g_allow),
                deny=list(g_deny),
                has_conditions=g_cond,
                unresolved_policies=list(g_unresolved),
            )
        )

    return Account(principals=principals)


def collect_from_aws(profile: str | None, out_path: str) -> None:
    """Pull live IAM data with boto3 and write the raw dump to out_path.

    boto3 (and botocore) are imported lazily so the offline `analyze`
    path needs no third-party packages installed. Predictable failures
    -- missing profile, missing/invalid credentials, insufficient
    permissions -- are caught and turned into clear, actionable messages
    instead of raw tracebacks.
    """
    try:
        import boto3
    except ImportError:
        raise SystemExit(
            "Live collection needs boto3.  Install it with:  pip install -e '.[aws]'\n"
            "For now you can run `analyze` against the fixture in fixtures/ with no AWS at all."
        )

    from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

    try:
        session = boto3.Session(profile_name=profile) if profile else boto3.Session()
        iam = session.client("iam")

        pages = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
        paginator = iam.get_paginator("get_account_authorization_details")
        for page in paginator.paginate():
            for key in pages:
                pages[key].extend(page.get(key, []))
    except ProfileNotFound:
        raise SystemExit(
            f"AWS profile '{profile}' not found.\n"
            f"Set it up with:  aws configure --profile {profile}"
        )
    except NoCredentialsError:
        raise SystemExit(
            "No AWS credentials found for this profile.\n"
            "Re-run:  aws configure --profile <name>"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            raise SystemExit(
                "Access denied. This identity lacks iam:GetAccountAuthorizationDetails.\n"
                "Attach a read policy like IAMReadOnlyAccess to the user."
            )
        raise SystemExit(f"AWS error ({code}): {err.response['Error']['Message']}")

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(pages, fh, indent=2, default=str)
