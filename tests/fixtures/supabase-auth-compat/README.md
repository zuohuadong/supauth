# Supabase full-stack compatibility fixture

The strict `bun run test:supabase-auth-compat` gate expects a disposable
Supabase project with:

- `20260719000000_full_stack.sql` applied to its database;
- the `functions/compat-claims` Function deployed with JWT verification enabled;
- stock GoTrue OAuth Server enabled with an asymmetric signing key;
- `SUPABASE_FULLSTACK_URL`, a public API key, and an admin API key available to
  the test process. Prefer `SUPABASE_FULLSTACK_PUBLISHABLE_KEY` and
  `SUPABASE_FULLSTACK_SECRET_KEY`; legacy `SUPABASE_FULLSTACK_ANON_KEY` and
  `SUPABASE_FULLSTACK_SERVICE_ROLE_KEY` remain supported as fallbacks.

The suite creates two temporary users, proves cross-user RLS and Storage
isolation, observes a real Postgres Change through Realtime, invokes the real
Function, and removes its users, rows, and object afterward. Use only a
disposable verification project; never point the service-role key at production.
