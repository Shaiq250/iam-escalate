# IAM escalation report

Found **2** escalation path(s) to admin.

## [HIGH] low-larry → admin  (2 hops)

```
low-larry  --[Assume role (sts:AssumeRole)]-->  admin-role  --[Self-attach a managed admin policy (iam:AttachUserPolicy)]-->  admin
```

Steps:
1. `low-larry` → `admin-role` — Assume role (sts:AssumeRole)
2. `admin-role` → `admin` — Self-attach a managed admin policy (iam:AttachUserPolicy)
   - Exploit: `aws iam attach-user-policy --user-name admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`
   - Fix: Remove iam:AttachUserPolicy from admin-role, or scope it with a permissions boundary / condition so it cannot attach privileged policies.

---

## [HIGH] admin-role → admin  (1 hop)

```
admin-role  --[Self-attach a managed admin policy (iam:AttachUserPolicy)]-->  admin
```

Steps:
1. `admin-role` → `admin` — Self-attach a managed admin policy (iam:AttachUserPolicy)
   - Exploit: `aws iam attach-user-policy --user-name admin-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess`
   - Fix: Remove iam:AttachUserPolicy from admin-role, or scope it with a permissions boundary / condition so it cannot attach privileged policies.

---
