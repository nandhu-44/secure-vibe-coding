# Supabase / Firebase / BaaS secure baseline

Vibe-coded apps often talk to the database **directly from the browser**. Then the security rules **are** the backend. Missing or permissive rules are a common cause of data exposure in BaaS-backed apps.

## Supabase
- **Enable RLS on every table** in exposed schemas (`alter table x enable row level security;`). A table without RLS is readable and writable by anyone with the anon key, which is public by design.
- Write policies with `auth.uid()`:
  ```sql
  create policy "owner can read" on notes for select using (auth.uid() = user_id);
  create policy "owner can insert" on notes for insert with check (auth.uid() = user_id);
  create policy "owner can update" on notes for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
  ```
- Never trust `user_metadata` (user-editable) in policies. Use `app_metadata` or a roles table.
- The `service_role` key bypasses RLS: **server only**, never `NEXT_PUBLIC_`/`VITE_`.
- `security definer` functions: set `search_path`, check `auth.uid()` inside, revoke execute from `anon` if not needed.
- Storage buckets: private by default, with policies on `storage.objects`.
- Run the Supabase Security Advisor / `supabase db lint`.

## Firebase
- Firestore/RTDB/Storage rules must never be `allow read, write: if true;` (or test mode with an expiry date).
  ```
  match /users/{uid}/notes/{noteId} {
    allow read, write: if request.auth != null && request.auth.uid == uid;
  }
  ```
- Validate fields in rules (`request.resource.data.keys().hasOnly([...])`, types, sizes) because clients can write anything.
- Enable App Check. Restrict API keys by app/domain in the GCP console (Firebase web API keys are public identifiers, not secrets).
- Privileged operations (payments, roles) go in Cloud Functions using the Admin SDK, with auth checks.

## General BaaS
- Treat every client-side query as attacker-controlled. Rules and policies are the authz layer.
- Test policies with a second test user. Try to read and write the first user's rows.
