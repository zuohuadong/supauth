# Authorization Boundary

## Decision

SupaCloud is the authority for platform control-plane RBAC. Each business
application is the authority for its own relationship-based authorization
(ReBAC) and workflow authorization.

SupAuth provides the Admin Console, management facade, projection contract,
and reusable authorization packages. It does not become a duplicate RBAC
database or a centralized ReBAC/PDP service.

## Ownership

| Capability | Authority | SupAuth responsibility |
| --- | --- | --- |
| Platform roles and permissions | SupaCloud Management API | Expose governance APIs and UI through the server-side facade |
| Organization and application assignments | SupaCloud Management API | Validate and present project-scoped assignments |
| JWT compatibility projection | SupaCloud -> GoTrue metadata | Consume the approved bounded `app_metadata.supaoauth.projects[projectRef]` projection |
| Business memberships and relationships | Application PostgreSQL schema | Provide `@supauth/authorization-core` and adapter contracts without owning facts |
| Workflow authorization | Application RPCs and RLS | Provide PostgreSQL/RLS generators and conformance checks without bypassing command gates |
| Identity and tokens | GoTrue | Preserve standard Supabase Auth behavior; never replace the issuer |

## Runtime Rules

- RBAC handles coarse product access with exact permission identifiers such as
  `users.read` or `reports.export`.
- ReBAC decisions use the application's current local facts for object,
  project, assignment, ownership, and reviewer-separation checks.
- `@supauth/authorization-core` is a request-boundary contract, not a remote
  policy decision point and not a cross-request authorization cache.
- `@supauth/authorization-postgres` generates reviewable helpers and RLS
  policies; it does not create or own application membership, role, or
  assignment tables.
- Missing, revoked, ambiguous, or malformed authorization facts fail closed;
  resolver infrastructure failure is reported distinctly as unavailable.
- UI gating is convenience only. API handlers, Edge Functions, RPCs, and RLS
  remain the enforcement boundaries.

## Explicit Non-Goals

SupAuth must not:

- copy application memberships, assignments, or workflow relationships into
  SupAuth or SupaCloud RBAC;
- use the JWT top-level `role` claim for business roles;
- require a remote ReBAC lookup for every application database row;
- replace application-owned state-machine, maker-checker, or audit decisions.

## Integration Contract

SupaCloud supplies the authoritative Management API, platform runtime,
GoTrue integration, and PostgreSQL/RLS substrate. SupAuth supplies the
product-facing governance facade, compatibility projection semantics, and
optional application-local authorization packages. Native SupaCloud/GoTrue
applications may use the packages without installing SupAuth.

See [`docs/application-authorization-kit.md`](application-authorization-kit.md)
and [`docs/rbac-supabase-compatibility.md`](rbac-supabase-compatibility.md).
