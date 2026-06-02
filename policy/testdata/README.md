# Policy Test Inputs

Run after installing OPA:

```bash
opa eval -d policy/policy.rego -i policy/testdata/user_get_users.json "data.zerotrust.authz.allow"
opa eval -d policy/policy.rego -i policy/testdata/user_get_admin_denied.json "data.zerotrust.authz.allow"
opa eval -d policy/policy.rego -i policy/testdata/admin_get_admin.json "data.zerotrust.authz.allow"
opa eval -d policy/policy.rego -i policy/testdata/user_post_resource_denied.json "data.zerotrust.authz.allow"
opa eval -d policy/policy.rego -i policy/testdata/user_post_resource_allowed.json "data.zerotrust.authz.allow"
```

Expected results:

- `user_get_users.json`: `true`
- `user_get_admin_denied.json`: `false`
- `admin_get_admin.json`: `true`
- `user_post_resource_denied.json`: `false`
- `user_post_resource_allowed.json`: `true`
