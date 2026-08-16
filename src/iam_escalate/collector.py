"""Turn AWS IAM data into our model.

Two entry points:
  load_account_from_file(path)  -> parse a saved JSON dump (no AWS, no deps)
  collect_from_aws(profile)     -> pull live data via boto3 (boto3 optional)

A principal's effective permissions are gathered from all three sources,
each run through the same _extract_from_policies helper:
  - inline policies (Allow + Deny)                 [2a]
  - attached managed policies (resolved from dump) [2b]
  - group-inherited policies (for users)           [2c]
Deny is honoured across every source; a managed policy whose document
isn't in the dump is recorded in unresolved_policies (flagged, not lost).
"""

from __future__ import annotations

import json

from .model import Account, Principal


def _statements_from_policy_doc(doc: dict) -> tuple[set[str], set[str], bool]:
    """Return (allow_actions, deny_actions, has_conditions) from one document."""
    allow: set[str] = set()
    deny: set[str] = set()
    has_conditions = False
    for stmt in doc.get("Statement", []):
        if stmt.get("Condition"):
            has_conditions = True
        effect = stmt.get("Effect")
        if effect == "Allow":
            target = allow
        elif effect == "Deny":
            target = deny
        else:
            continue
        raw = stmt.get("Action", [])
        for a in [raw] if isinstance(raw, str) else raw:
            target.add(a)
    return allow, deny, has_conditions


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
) -> tuple[set[str], set[str], bool, list[str]]:
    """Fold one set of inline + attached-managed policies into permissions.

    Shared by users, roles, and groups -- the single place that turns
    policy documents into (allow, deny, has_conditions, unresolved).
    """
    allow: set[str] = set()
    deny: set[str] = set()
    has_conditions = False
    unresolved: list[str] = []

    for inline in inline_policies:
        a, d, c = _statements_from_policy_doc(inline.get("PolicyDocument", {}))
        allow |= a
        deny |= d
        has_conditions = has_conditions or c

    for att in attached_managed:
        parn = att.get("PolicyArn")
        doc = policy_index.get(parn)
        if doc is None:
            unresolved.append(att.get("PolicyName") or parn or "<unknown>")
            continue
        a, d, c = _statements_from_policy_doc(doc)
        allow |= a
        deny |= d
        has_conditions = has_conditions or c

    return allow, deny, has_conditions, unresolved


def _build_group_index(
    groups: list, policy_index: dict[str, dict]
) -> dict[str, tuple[set[str], set[str], bool, list[str]]]:
    """Resolve each group's policies once, keyed by group name."""
    index: dict[str, tuple[set[str], set[str], bool, list[str]]] = {}
    for g in groups:
        index[g["GroupName"]] = _extract_from_policies(
            g.get("GroupPolicyList", []),
            g.get("AttachedManagedPolicies", []),
            policy_index,
        )
    return index


def _user_principal(user: dict, policy_index, group_index) -> Principal:
    """Build a user Principal from its own policies plus inherited group policies."""
    allow, deny, has_conditions, unresolved = _extract_from_policies(
        user.get("UserPolicyList", []),
        user.get("AttachedManagedPolicies", []),
        policy_index,
    )

    # Fold in every group the user belongs to.
    for gname in user.get("GroupList", []):
        g = group_index.get(gname)
        if g is None:
            continue  # group referenced but not present in the dump
        g_allow, g_deny, g_cond, g_unresolved = g
        allow |= g_allow
        deny |= g_deny
        has_conditions = has_conditions or g_cond
        unresolved.extend(g_unresolved)

    # Drop duplicate unresolved names while preserving order.
    unresolved = list(dict.fromkeys(unresolved))

    return Principal(
        name=user["UserName"],
        arn=user["Arn"],
        ptype="user",
        allowed_actions=allow,
        denied_actions=deny,
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
        principals.append(
            Principal(
                name=role["RoleName"],
                arn=role["Arn"],
                ptype="role",
                allowed_actions=allow,
                denied_actions=deny,
                has_conditions=has_conditions,
                unresolved_policies=unresolved,
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
