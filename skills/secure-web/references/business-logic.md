# Business-logic security

Logic flaws are the bugs AI-generated apps ship most often and scanners miss most often. The code "works", but the *rules of the business* can be bent. Before writing any flow that moves **money, credits, inventory, permissions, or identity**, list the abuse cases below and code against them.

## Checklist by pattern

### Trusting client-side values [CWE-602, CWE-472]
| Client sends | Attack | Do instead |
|---|---|---|
| `price`, `total`, `discount` | Pay $0.01 | Look up price by product ID server-side and recompute the total |
| `userId`, `ownerId`, `accountId` | Act as someone else | Use `session.user.id` |
| `role`, `isAdmin`, `plan`, `verified` | Privilege escalation | Server-controlled columns, never writable via API |
| `quantity: -5` | Negative total / refund | Positive int, `1 ≤ q ≤ MAX` |
| `quantity: 1e9` / huge arrays | DoS, overflow | Upper bounds, array length caps |
| `currency` | Pay in a cheaper currency | Currency fixed by product/account |
| Hidden form fields, disabled buttons | Trivially bypassed | Re-check every condition server-side |

### Multi-step flows & state machines [CWE-841]
- Model status as an enum with an explicit transition table, and check it in the same transaction as the update:
  ```python
  ALLOWED = {"cart": {"pending_payment"}, "pending_payment": {"paid", "cancelled"}, "paid": {"shipped", "refunded"}}
  def transition(order, new):
      if new not in ALLOWED.get(order.status, set()):
          raise Conflict(f"cannot go from {order.status} to {new}")
  ```
- Don't let users call step 3 without completing step 2 (e.g. `/checkout/confirm` must verify payment succeeded with the provider, not a client flag).
- Email/phone change: verify the **new** address before switching. Notify the old one.
- Account deletion and recovery: re-authenticate first (step-up).

### Race conditions / TOCTOU [CWE-362, CWE-367]
Classic exploits are redeeming a gift card 10× in parallel, withdrawing more than the balance, or using one invite twice.
- **Atomic conditional update** (best):
  ```sql
  UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1 RETURNING balance;
  -- 0 rows → insufficient funds
  ```
- **Row locks**: `SELECT … FOR UPDATE` inside a transaction (`select_for_update()` in Django, `with_for_update()` in SQLAlchemy, `$transaction` + raw lock in Prisma).
- **Unique constraints** for one-time actions: `UNIQUE(coupon_id, user_id)`, `UNIQUE(invite_token)`, then catch the violation.
- **Idempotency keys** for payment/order creation: the client sends `Idempotency-Key`. Store `(key, user) → response` and return the stored response on retry.
- Never do "read balance in app → check → write new balance" without a lock.

### Money & numbers [CWE-681, CWE-190]
- Use integer minor units (cents) or `Decimal`. Never floats.
- Round once, at a defined step, with a defined rule.
- Check for overflow and negative results. Ensure refunds never exceed what was captured.

### One-time & time-limited tokens [CWE-294, CWE-613]
Reset links, magic links, email verification, invites, OTPs, and coupons must be: random (CSPRNG, ≥128 bits) · stored hashed · single-use (atomically consumed) · short expiry · bound to the user/purpose · rate-limited on verify.

### Webhooks & third-party callbacks [CWE-345]
1. Verify the HMAC signature over the **raw** body (constant-time compare).
2. Reject old timestamps (>5 min) to stop replays.
3. Dedupe by event ID (unique constraint).
4. **Re-fetch the object from the provider API** (e.g. `stripe.checkout.Session.retrieve`) before granting value. Don't trust amounts in the payload alone.
5. Grant entitlements idempotently.

### Payments (Stripe-style)
- Create the Checkout Session/PaymentIntent server-side with server-side prices (`price` IDs).
- Fulfil only from the verified webhook (`checkout.session.completed`), not from the success redirect URL.
- Store the provider's customer/session IDs and map them to your user server-side.

### Free-tier and quota abuse [CWE-799, CWE-770]
- Per-user and per-IP quotas on expensive actions (LLM calls, SMS, email, exports, image generation).
- Prevent multi-account farming where it matters: email verification, phone verification, device fingerprinting, CAPTCHA on signup.
- Hard spending caps on third-party APIs. Alert on spikes.

### Enumeration & information leaks [CWE-203, CWE-204]
- Identical responses and timing for "no such user" vs "wrong password", and "email already registered" (send an email instead of telling the UI).
- Random IDs for private resources. Paginated APIs never return other tenants' rows.
- Don't expose internal IDs, emails, or stack traces in errors.

### Invitations, sharing & tenancy
- Invite acceptance checks that the token matches the logged-in user's email (or explicitly allows any).
- Shared links: random token, revocable, optional expiry, read-only unless stated.
- When a user leaves an org, revoke their sessions and API keys scoped to it.

### Admin & support tools
- Separate admin authz (role + ideally MFA + IP allowlist). Log every admin action.
- Impersonation must be explicit, logged, time-limited, and must not allow password or MFA changes.

## Abuse-case prompt to run mentally
> "If I were a malicious logged-in user with curl and two terminals, how would I get something for free, see someone else's data, or do this action more times than allowed?"
