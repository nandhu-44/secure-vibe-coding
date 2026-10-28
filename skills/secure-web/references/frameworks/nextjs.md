# Next.js (App Router) secure baseline

**Mental model:** every Server Action, Route Handler, and server component that reads data is reachable by an attacker with curl. `"use server"` functions are public POST endpoints.

## Rules
1. **Authorize inside each Server Action / Route Handler**, not only in `middleware.ts`. Middleware is a convenience layer: path matching is easy to get wrong, and in March 2025, CVE-2025-29927 allowed bypassing it with the `x-middleware-subrequest` header.
   ```ts
   "use server";
   export async function deletePost(postId: string) {
     const session = await auth();
     if (!session?.user) throw new Error("unauthorized");
     const id = z.string().uuid().parse(postId);
     const res = await db.post.deleteMany({ where: { id, authorId: session.user.id } }); // scoped
     if (res.count === 0) throw new Error("not found");
     revalidatePath("/posts");
   }
   ```
2. **Validate all action arguments** with zod. TypeScript types do not exist at runtime.
3. **Data Access Layer**: centralize DB reads in `server-only` modules (`import "server-only"`) that check auth and return DTOs. Never pass full DB rows (with `passwordHash`, emails, tokens) into client components, because props get serialized to the browser.
4. **Secrets**: only `process.env.X` in server code. Anything `NEXT_PUBLIC_*` is shipped to every visitor.
5. **Headers/CSP** in `next.config.js` `headers()` or middleware. Use nonce-based CSP for scripts.
6. **Rate-limit** Server Actions and auth routes (`@upstash/ratelimit`). See rate-limiting.md.
7. **`dangerouslySetInnerHTML`** only with DOMPurify-sanitized content (`isomorphic-dompurify`).
8. **Redirects**: `redirect()` only to internal paths. Validate `callbackUrl`/`next` params.
9. **Image optimizer / remotePatterns**: restrict `images.remotePatterns` to known hosts (otherwise it is an SSRF/cost risk).
10. **Auth.js**: set `AUTH_SECRET`, use database or JWT sessions with short maxAge, enable `trustHost` only behind a known proxy.

## Supabase / Prisma notes
- Prisma: never `$queryRawUnsafe` with interpolation. Use the `$queryRaw` tagged template (it parameterizes).
- Supabase from the browser: **RLS must be enabled on every table** and policies must reference `auth.uid()`. The `service_role` key is server-only. See baas.md.
