# Production Runbook

This runbook covers release, rollback, restore, and incident triage for SupaOAuth and the underlying Supabase-compatible runtime.

## Release Gate

1. Run local gate: `bun run release:gate`.
2. For live cutover, set `RUN_LIVE_RELEASE_GATE=1`, `SUPAUTH_PUBLIC_URL`, and `SUPAUTH_INSTALLED_RUNTIME_URL`; this runs the installed SupaCloud Function/Pages verifier. `SUPAUTH_INSTALLED_BASE_URL` remains supported for existing SupaCloud installs. If `RUN_SUPABASE_RUNTIME_COMPAT=1` or `RUN_SUPABASE_OAUTH21_COMPAT=1` is also set, the release gate runs those suites in strict mode, so missing live Auth credentials, OAuth access/refresh tokens, or skipped token-shape checks fail the release.
3. CI branch protection must require the `Supabase Auth Compatibility` job. It runs `REQUIRE_SUPABASE_AUTH_COMPAT=1 bun run test:supabase-auth-compat`, so missing live Auth secrets or broken `supabase-js` auth coverage fail the build instead of passing as a smoke-only run. Set `LIVE_SUPABASE_AUTH_URL` to the public GoTrue/Auth origin that serves `/auth/v1/.well-known/openid-configuration` and `/auth/v1/.well-known/jwks.json`. Prefer `LIVE_SUPABASE_PUBLISHABLE_KEY` and `LIVE_SUPABASE_SECRET_KEY`; the legacy anon/service-role secrets remain fallback inputs. The project runtime route preservation checks stay in `scripts/verify-supacloud-installed-app.ts`.
4. Confirm the generated `artifacts/<release>/release-manifest.json` contains commit, OpenAPI hash, SupaCloud app manifest hash, installed app verification path, and live gate status.
5. Deploy the artifact through SupaCloud using `artifacts/<release>/supacloud-app-manifest.json`.
6. Switch traffic only after `scripts/verify-supacloud-installed-app.ts` passes against the installed Function/Pages routes and preserved `/auth/v1/*`, `/rest/v1/*`, `/storage/v1/*`, `/realtime/v1/*`, and `/functions/v1/*` runtime routes.
7. Before the V9/V10 webhook retirement, confirm the encrypted database backup is restorable. If installation reports `reason_code=legacy_webhook_data_present`, recreate the definitions in SupaCloud Secret Manager, rotate receivers to the `X-SupaCloud-*` signature protocol, verify a test delivery, and only then clear the backed-up legacy rows. Never print or export a plaintext webhook secret during this process.

## Webhook Delivery Boundary

- Treat `organization.created`, `organization.invitation_created`, `organization.member_added`, `organization.member_updated`, `organization.member_removed`, `role.assigned`, and `role.revoked` as `transactional`: the SupaCloud control-plane mutation and outbox insert commit together.
- Treat published user, Application, Connector, and Organization Template events as `post_mutation`: the underlying mutation completes before SupaOAuth submits the event to SupaCloud. There is no cross-system transaction or saga between a GoTrue mutation and the SupaCloud outbox.
- Durable retry, DLQ, and replay guarantees start only after the event has been accepted into the SupaCloud outbox. A failed post-mutation submission does not automatically roll back the already successful underlying mutation.
- During an incident, read `/v1/webhooks/events` and use its `catalog[].guarantee` value to identify the boundary. For `post_mutation` failures, verify the underlying resource and the outbox independently before deciding whether to repeat the administrative action; do not assume replay can reconstruct an event that never entered the outbox.

## Rollback

1. Ask SupaCloud to roll the SupAuth Function bundle and Admin Pages artifact back to the previous manifest version.
2. Verify SupaCloud route bindings still send `/api/*`, `/v1/public/*`, hosted pages, and `/oauth/*` to the SupAuth Function.
3. Verify `https://auth.example.com/api/v1/health` and the generated manifest still declare `http_runtime=supacloud-functions-only`.
4. Do not modify SupaCloud managed runtime routes during rollback unless the manifest changed preserved runtime routing.
5. If provisioning records drifted, run `POST /v1/provisioning/:projectRef/rollback` to reset reconcile state.
6. V9 permission revocation can be rolled back with the previous migration grants only while the legacy tables still exist. Once V10 drops empty tables, restore requires the encrypted pre-upgrade backup; the previous Function must not recreate or resume the local webhook worker.

## Backup And Restore

1. Backup metadata: `DATABASE_URL=... BACKUP_DIR=backups/<id> bun run backup:drill`.
2. Store the SQL dump and manifest with project config, SupaCloud route/domain inventory, OAuth client secret inventory, webhook secret inventory, and storage object inventory.
   Keep the dump encrypted and access-controlled because a pre-V10 backup may contain retired webhook signing secrets.
3. Restore to a new target: `RESTORE_DATABASE_URL=... BACKUP_DIR=backups/<id> bun run scripts/backup-restore-drill.ts restore`.
4. Reconcile the new project using `POST /v1/provisioning/:projectRef/reconcile`.
5. Run P0-16 live fixture and admin smoke test before accepting the restore.

## Incident Triage

- Auth timeouts: check SupaCloud runtime health, GoTrue health, Postgres active connections, memory, and swap.
- `supabase-js` session failures: run `tests/integration/supabase-compat/supabase-js.test.ts` with live env and inspect `/auth/v1/token`, `/auth/v1/user`, JWKS, and issuer alignment.
- OAuth consent issues: reproduce with the current user's GoTrue `/user/oauth/grants`
  and authorization details/consent endpoints, then correlate
  `supaoauth.oauth_consent_decisions`, application bindings, and
  `oauth.consent.*` / `my_account.grant.revoked` audit events. Stock GoTrue does
  not expose an administrator Grant facade; treat legacy
  `supaoauth.user_consents` as read-only history only.
- RBAC/RLS issues: verify `supaoauth.has_permission(...)`, `supaoauth.authorize(...)`, and `supaoauth.has_org_permission(...)` grants, then run the RLS migration assistant.
- Storage asset failures: verify `branding` is public, `avatars` is private, and signed URLs are generated on demand.

## Recovery Objectives

- Staging RPO: 24 hours.
- Staging RTO: 2 hours.
- Production target RPO: 1 hour after external backup automation is connected.
- Production target RTO: 30 minutes after release and restore automation is connected.
