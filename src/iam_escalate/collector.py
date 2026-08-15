"""Turn AWS IAM data into our model.

Two entry points:
  load_account_from_file(path)  -> parse a saved JSON dump (no AWS, no deps)
  collect_from_aws(profile)     -> pull live data via boto3 (boto3 optional)

Permission sources folded into a principal's effective permissions:
  - inline policies (Allow + Deny)                          [2a]
  - attached managed policies resolved from the dump         [2b]
  - group-inherited policies                                 [2c, todo]
All sources feed the same _statements_from_policy_doc extractor. A
managed policy whose document isn't present in the dump's Policies list
is recorded in the principal's unresolved_policies (flagged, not ignored).
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
    """Pull the active policy document out of a Policies-list entry.

    Each entry carries a PolicyVersionList; the active one is marked
    IsDefaultVersion (or matches DefaultVersionId). boto3 has already
    URL-decoded the document into a plain dict.
    """
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


def _principal_from_entity(
    name: str,
    arn: str,
    ptype: str,
    inline_policies: list,
    attached_managed: list,
    policy_index: dict[str, dict],
) -> Principal:
    """Build a Principal from its inline policies + attached managed policies."""
    allow: set[str] = set()
    deny: set[str] = set()
    has_conditions = False
    unresolved: list[str] = []

    # Inline policies embedded directly on the entity.
    for inline in inline_policies:
        a, d, c = _statements_from_policy_doc(inline.get("PolicyDocument", {}))
        allow |= a
        deny |= d
        has_conditions = has_conditions or c

    # Attached managed policies, resolved from the dump's Policies list.
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

    return Principal(
        name=name,
        arn=arn,
        ptype=ptype,
        allowed_actions=allow,
        denied_actions=deny,
        has_conditions=has_conditions,
        unresolved_policies=unresolved,
    )


def load_account_from_file(path: str) -> Account:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    policy_index = _build_policy_index(data.get("Policies", []))
    principals: list[Principal] = []

    for user in data.get("UserDetailList", []):
        principals.append(
            _principal_from_entity(
                user["UserName"],
                user["Arn"],
                "user",
                user.get("UserPolicyList", []),
                user.get("AttachedManagedPolicies", []),
                policy_index,
            )
        )

    for role in data.get("RoleDetailList", []):
        principals.append(
            _principal_from_entity(
                role["RoleName"],
                role["Arn"],
                "role",
                role.get("RolePolicyList", []),
                role.get("AttachedManagedPolicies", []),
                policy_index,
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
