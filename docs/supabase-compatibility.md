# Supabase Compatibility Specification

SupaOAuth must remain fully compatible with the Supabase ecosystem. Any feature that breaks the following guarantees is a release blocker.

The enterprise IAM rule is: **SupaOAuth enhances Supabase Auth, it does not replace Supabase Auth**. Enterprise user-center, organization, permission-governance, audit, and approval features live above the Supabase-compatible runtime. They must not change the public GoTrue protocol surface that existing Supabase applications, SDKs, PostgREST, Storage, Realtime, Edge Functions, and RLS policies rely on.

The upstream version rule is: **SupaOAuth must work with the stock upstream GoTrue/Supabase Auth runtime and official Supabase SDKs**. A supported deployment must not require a SupaOAuth-patched GoTrue binary, a forked `@supabase/supabase-js`, a forked Auth UI package, or custom `/auth/v1/*` semantics. SupaOAuth integrations must use documented GoTrue/Supabase extension points, SupaCloud Management API, SupaCloud Functions/Pages, additive schema-v2 metadata at `app_metadata.supaoauth.projects[projectRef]`, and compatibility gates that can be rerun when SupaCloud upgrades the upstream runtime.

## Must-Compatible (Release Blocker)

### SC-1: supabase-js SDK

Business applications must continue using `supabase-js` unmodified:

- `supabase.auth.signInWithOAuth()` triggers GoTrue's existing OAuth flow
- `supabase.auth.getSession()` returns valid GoTrue sessions
- `supabase.auth.getUser()` returns GoTrue user objects
- `supabase.auth.signOut()` invalidates GoTrue sessions
- Token refresh works through GoTrue's existing endpoint

SupaOAuth does not intercept or modify the `supabase-js` auth transport layer.

Application code and hosted UI bridges should keep using official Supabase SDK packages. SupaOAuth may publish adapter packages such as `@supauth/sdk-auth-ui`, but those adapters must configure or wrap official SDKs rather than depending on a fork.

### SC-1a: Upstream GoTrue Version Compatibility

SupaOAuth must tolerate SupaCloud upgrading the underlying GoTrue/Supabase Auth runtime as long as the documented Supabase Auth protocol and extension points remain compatible:

- `/auth/v1/*` remains owned by the upstream GoTrue runtime; SupaOAuth must not shadow it with a private protocol implementation.
- GoTrue discovery, JWKS, token, refresh, MFA, user, and OAuth endpoints are treated as upstream contracts, not SupaOAuth-owned internals.
- SupaOAuth-specific behavior belongs in SupaCloud Functions/Pages, SupaCloud Management API facade calls, Auth Hooks, the additive schema-v2 `app_metadata.supaoauth.projects[projectRef]` projection, or installed compatibility helpers.
- Any missing platform capability should be added to SupaCloud or upstream integration layers, not by requiring a custom GoTrue fork for normal `gotrue` mode.
- Release gates must keep live Supabase Auth compatibility checks runnable against the current deployed upstream version.

The release matrix retains unmodified GoTrue v2.192.0 as the regression floor
and uses unmodified v2.196.0 as the current runtime target. Set
`SUPABASE_AUTH_COMPAT_VERSION` to the exact matrix version; it is only an
expectation, never a capability source. Both live session preparation and the
OAuth compatibility suite must read `/auth/v1/health` and require its structured
`version` to exactly match that expectation before continuing. A non-success
health response, invalid or missing version, or mismatch fails the gate. The
only accepted matrix values are `v2.192.0` and `v2.196.0`; an intermediate or
unknown declared version also fails rather than inheriting floor behavior. The
default expectation remains `v2.196.0`, so pointing the default gate at an older
runtime cannot silently disable current-target assertions. A v2.192 floor run
must explicitly declare `v2.192.0` and connect to health read-back reporting
that exact version before current-target discovery and scope assertions are disabled.
Each version must run the same strict
`bun run test:supabase-auth-compat` gate with zero
failures and zero skips. Coverage includes password/session/refresh, OAuth
authorization code with PKCE, UserInfo, TOTP/AAL, owner-based PostgREST RLS,
private Storage isolation, Realtime Postgres Changes, Edge Functions, and the
exact RFC 8693 `unsupported_grant_type` response. On v2.193.0+ the TOTP case also
deletes the verified factor through the admin API, refreshes the same session,
and requires its JWT to downgrade from `aal2` to `aal1` while AMR remains a list
of authentication `method` entries. The disposable database and Function assets
are versioned under `tests/fixtures/supabase-auth-compat/`.

Live compatibility gates prefer Supabase's modern
`SUPABASE_PUBLISHABLE_KEY`/`SUPABASE_SECRET_KEY` pair, including the matching
`SUPABASE_FULLSTACK_*` overrides for a dedicated fixture. Legacy
`SUPABASE_ANON_KEY`/`SUPABASE_SERVICE_ROLE_KEY` variables remain supported as
fallbacks for runtimes that still accept JWT API keys. The modern key always
wins when both forms are configured, so a rejected legacy HS256 service-role
JWT cannot mask a working secret key on upgraded GoTrue runtimes.

Before upgrading either version, back up the tenant `auth` schema. The stock
v2.192.0 startup applies the additive
`20260625000000_add_custom_claims_allowlist.up.sql` migration, which adds
`auth.custom_oauth_providers.custom_claims_allowlist text[] NOT NULL DEFAULT
'{}'`; acceptance must read that column back after GoTrue starts. The
v2.192.0-to-v2.196.0 upstream changes require no SupaOAuth database migration,
so the v2.196.0 rollout must not invent or run one for this upgrade.

GoTrue v2.196.0 discovery must advertise `offline_access`. The current-target
compatibility session requests it and must receive a refresh token whose access
token preserves the granted scope. The v2.192.0 floor keeps the earlier scope
request because it predates that discovery contract. GoTrue also refreshes
`last_sign_in_at` when issuing v2 refresh-token sessions; SupaOAuth preserves
the authoritative user field without manufacturing or comparing timestamps.

When GoTrue returns HTTP 403 with a structured `code` or `error_code` equal to
`user_banned`, SupaOAuth exposes only the fixed `user_banned` account error. It
does not infer this state from messages or forward the upstream payload. Hosted
Account Center pages clear the local page session and explain that the account
is disabled; unrelated 403 responses remain `upstream_forbidden` and keep the
local session intact.

GoTrue v2.196.0 SCIM support, including its metadata endpoints, remains dark. SupaOAuth must not enable
`GOTRUE_EXPERIMENTAL_SCIM_ENABLED` or advertise an administration surface while
the capability is not explicitly accepted by the product.

GoTrue v2.193.0 provider-linking domains remain opt-in.
`GOTRUE_EXPERIMENTAL_PROVIDER_LINKING_DOMAINS` is passed only when an
administrator supplies a non-empty mapping such as
`custom:github=social,custom:google=social`. The deprecated
`experimental.providers_with_own_linking_domain` list is accepted only as
one-way migration input, normalized into the canonical map, and never rendered
as the deprecated GoTrue environment variable.

This automatic linking-domain experiment is distinct from GoTrue manual
identity linking. The Account Center manual ceremony is separately opt-in and
requires both `manual_linking_enabled=true` in authoritative GoTrue auth config
and the Account Center identities module to be enabled.

### SC-2: auth.users

When `runtime_mode=gotrue`, user identity lives in GoTrue's `auth.users` table:

- SupaOAuth metadata tables reference `auth.users.id` via foreign key
- SupaOAuth does not create a parallel user table
- User CRUD operations are proxied through the SupaCloud adapter to GoTrue
- SupaOAuth may extend user profiles in a separate metadata table keyed by `auth.users.id`

### SC-3: JWT Claims for RLS

Access tokens must preserve all claims required by Supabase Auth's Custom Access Token Hook contract and by common Supabase RLS policies:

| Claim | Source | Usage |
| --- | --- | --- |
| `iss` | GoTrue | Issuer validation |
| `aud` | GoTrue | Token audience validation |
| `exp` | GoTrue | Token expiry |
| `iat` | GoTrue | Token issue time |
| `sub` | GoTrue | User identity in RLS policies |
| `role` | GoTrue | `anon` / `authenticated` / `service_role` runtime role switch |
| `aal` | GoTrue | MFA assurance checks, for example `aal2` RLS gates |
| `session_id` | GoTrue | Session identity and revocation correlation |
| `email` | GoTrue | User identity claim exposed by Supabase Auth |
| `phone` | GoTrue | User identity claim exposed by Supabase Auth |
| `is_anonymous` | GoTrue | Anonymous-user flow compatibility |

SupaOAuth must also preserve common Supabase metadata claims when they are present:

| Claim | Source | Usage |
| --- | --- | --- |
| `app_metadata` | GoTrue | Authorization-safe custom RLS claims and SupaOAuth enterprise projection |
| `user_metadata` | GoTrue | User profile claims; do not use for authorization |

SupaOAuth may add a schema-v2 container at `app_metadata.supaoauth`, but must never remove or alter the above required claims or existing metadata claims. The root contains only `schema_version`, `projects`, and valid `hook` metadata; current enterprise authorization fields live only at `app_metadata.supaoauth.projects[projectRef]`. Business roles must not replace the top-level `role` claim. Large permission sets should not be copied into every token by default; use a compact role/permission version and resolve full permissions through SupaCloud/SupaOAuth APIs or bounded RLS projections where needed.

OAuth 2.1 access tokens must also preserve `client_id` and `scope`. Tokens returned by the refresh-token grant are still Supabase JWTs and must pass the same standard-claim, runtime-role, OAuth-client/scope, and no-top-level-`supaoauth:*` checks. User identity remains in the standard `sub` claim; stock GoTrue v2.192+ does not require a separate `user_id` claim. `client_id` is the OAuth client boundary that RLS or application APIs can use for client-specific access control.

OAuth `scope` must remain the granted standard scope string. GoTrue carries it in the OAuth access-token JWT; the token endpoint response may omit `scope` when it is unchanged from the request. Treat scopes as Supabase OAuth/UserInfo/ID-token metadata; do not translate enterprise permissions into OAuth scope claims unless a future Supabase-compatible custom-scope mode is explicitly enabled for a project. Database access remains controlled by RLS, usually through `auth.uid()`, `auth.jwt() ->> 'client_id'`, and SupaOAuth versioned permission lookups.

### SC-4: OIDC Discovery and JWKS

- GoTrue's `/.well-known/openid-configuration` is the authoritative discovery document
- GoTrue's `/.well-known/oauth-authorization-server` is the authoritative OAuth 2.1 authorization-server metadata document
- GoTrue's `/.well-known/jwks.json` is the authoritative key set
- SupaOAuth does not replace or proxy these endpoints with its own signing

### SC-5: Supabase API Paths

The following Supabase runtime paths must remain accessible and functional:

| Path Pattern | Service |
| --- | --- |
| `/auth/v1/*` | GoTrue auth |
| `/.well-known/*` | OIDC discovery, JWKS |
| `/rest/v1/*` | PostgREST |
| `/storage/v1/*` | Storage API |
| `/realtime/v1/*` | Realtime WebSocket |
| `/functions/v1/*` | Edge Functions |

SupAuth Function paths must not conflict with these. The Management API facade uses the SupaCloud app route prefix `/api/v1/*`; there is no separate SupAuth service port in the supported runtime.

### SC-6: SupaCloud Project-Scoped Runtime

SupaOAuth must work inside a SupaCloud-created project:

- SupaCloud owns GoTrue, gateway routing, PostgREST, Storage, Realtime, and Functions runtime paths
- SupAuth installs only as SupaCloud Functions and Pages from the generated manifest
- SupAuth Management API is a Function facade over SupaCloud Management API plus SupAuth overlay data
- No standalone SupAuth service, systemd unit, pm2 process, webhook worker, or SupAuth-owned cron is supported

### SC-7: Single GoTrue Runtime

- GoTrue is the token issuer
- JWT is signed with the GoTrue JWT secret
- SupaOAuth is the control plane and BFF only
- All Supabase SDK flows work without modification
- The underlying GoTrue/Supabase Auth service can be a stock upstream version provided by SupaCloud
- `RUNTIME_MODE` is fixed to `gotrue`; any other configured value fails validation

## Optional-Compatible

### SC-8: Row Level Security Extensions

SupaOAuth may enhance RLS with the current project's object under `app_metadata.supaoauth.projects[projectRef]`:

- `roles` — bounded compact SupaOAuth role names or IDs
- `current_org_id` / `organization_ids` — current and accessible organization context
- `scopes` — optional project-specific API-scope hints when explicitly enabled; do not confuse this with the OAuth token response `scope`, and do not use it as the default enterprise database-permission source
- `permissions` — bounded resolved permission set for RLS helper compatibility
- `roles_count` / `permissions_count` plus `rbac_version` / `permissions_version` — cache invalidation and full-lookup markers for APIs that resolve roles or permissions outside the JWT

These claims are additive. They must not replace GoTrue's built-in claims. Roles are limited to 64, permissions to 256, and the complete project projection to 16 KiB. Oversize, unavailable, v1, or missing-project projections fail closed instead of partially authorizing.

RLS policies should keep native `auth.uid()` / `auth.jwt()` owner checks and use SupaOAuth helpers only as additive enterprise gates, for example `supaoauth.has_permission(...)` or `supaoauth.has_org_permission(...)`.

### SC-9: Storage and Realtime Auth

- Storage access tokens continue to work through GoTrue's existing JWT
- Realtime WebSocket auth uses the same GoTrue JWT
- SupaOAuth does not issue separate tokens for Storage or Realtime

### SC-10: Edge Functions Auth

- Edge Functions receive the same GoTrue JWT in `Authorization` header
- `supabase-js` Functions client continues to inject the token automatically
- SupaOAuth does not modify the Edge Functions auth chain

## Custom Claims Namespace

SupaOAuth-added claims use `app_metadata.supaoauth.projects[projectRef]`:
- SupaCloud projects the RBAC fields; the Supabase-compatible auth hook adds only bounded JIT membership and valid hook metadata.
- The root schema is exactly version `2`. Legacy root-level RBAC fields are not read or dual-written.
- RLS must use `supaoauth.current_project_claims()` or the higher-level authorization helpers so v1, absent, truncated, and unavailable projections fail closed.

## Verification Checklist

For each release, verify:

- [x] `supabase-js` can sign in, get session, refresh token, sign out
- [x] OAuth 2.1 metadata, authorization-code + PKCE, refresh-token, UserInfo, and unsupported-grant behavior pass `tests/integration/supabase-compat/oauth21.test.ts` against a real runtime
- [x] `auth.users` is the primary identity table (no parallel user table in gotrue mode)
- [x] JWT contains all required Supabase Auth claims (`iss`, `aud`, `exp`, `iat`, `sub`, `role`, `aal`, `session_id`, `email`, `phone`, `is_anonymous`)
- [x] JWT keeps authorization metadata in the schema-v2 `app_metadata.supaoauth.projects[projectRef]` entry, not the top-level `role` claim
- [x] OIDC discovery document is accessible at `/.well-known/openid-configuration`
- [x] OAuth authorization-server metadata is accessible at `/.well-known/oauth-authorization-server`
- [x] JWKS is accessible at `/.well-known/jwks.json`
- [x] A real GoTrue JWT passes owner-based RLS, private Storage isolation, Realtime Postgres Changes, and a JWT-protected Function via `tests/integration/supabase-compat/full-stack.test.ts`
- [x] Supabase API paths (`/auth/v1/*`, `/rest/v1/*`, `/storage/v1/*`, `/realtime/v1/*`, `/functions/v1/*`) remain functional
- [x] No SupaOAuth-patched GoTrue binary, forked `supabase-js`, forked Auth UI package, or private `/auth/v1/*` behavior is required in `runtime_mode=gotrue`
- [x] No management tokens or service-role keys appear in browser-visible code or `VITE_*` variables
- [x] Self-hosted deployment works without Supabase Cloud
- [x] `runtime_mode=gotrue` works with zero SupaOAuth-specific claims in the JWT
- [x] Token Exchange remains unsupported by GoTrue and is not advertised by SupaOAuth
- [x] No PAT, subject-token, outbound SAML IdP, recovery-code, or independent issuer surface is installed
