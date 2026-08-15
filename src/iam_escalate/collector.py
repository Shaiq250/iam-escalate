"""Turn AWS IAM data into our model.

Two entry points:
  load_account_from_file(path)  -> parse a saved JSON dump (no AWS, no deps)
  collect_from_aws(profile)     -> pull live data via boto3 (boto3 optional)

The file parser reads INLINE Allow statements only, which is enough to
drive the M0 example rule. Attached managed policies, group inheritance,
and Deny handling come in M2.
"""

from __future__ import annotations

import json

from .model import Account, Principal


def _actions_from_policy_doc(doc: dict) -> tuple[set[str], bool]:
    """Return (allowed_actions, has_conditions) from one policy document.

    M0 simplification: only Effect == Allow statements contribute actions.
    Any statement carrying a Condition sets has_conditions so M2/reporting
    can flag it for manual review.
    """
    actions: set[str] = set()
    has_conditions = False
    for stmt in doc.get("Statement", []):
        if stmt.get("Condition"):
            has_conditions = True
        if stmt.get("Effect") != "Allow":
            continue
        raw = stmt.get("Action", [])
        for a in [raw] if isinstance(raw, str) else raw:
            actions.add(a)
    return actions, has_conditions


def load_account_from_file(path: str) -> Account:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)

    principals: list[Principal] = []

    for user in data.get("UserDetailList", []):
        actions: set[str] = set()
        has_conditions = False
        for inline in user.get("UserPolicyList", []):
            a, c = _actions_from_policy_doc(inline.get("PolicyDocument", {}))
            actions |= a
            has_conditions = has_conditions or c
        principals.append(
            Principal(
                name=user["UserName"],
                arn=user["Arn"],
                ptype="user",
                allowed_actions=actions,
                has_conditions=has_conditions,
            )
        )

    # Roles parsed the same way (RolePolicyList); left minimal for M0.
    for role in data.get("RoleDetailList", []):
        actions = set()
        has_conditions = False
        for inline in role.get("RolePolicyList", []):
            a, c = _actions_from_policy_doc(inline.get("PolicyDocument", {}))
            actions |= a
            has_conditions = has_conditions or c
        principals.append(
            Principal(
                name=role["RoleName"],
                arn=role["Arn"],
                ptype="role",
                allowed_actions=actions,
                has_conditions=has_conditions,
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
