# Trust Health Checks and SSDD (planned)

Design note for a future WordPress identity-layer release (after the **0.1.32-ui16** canary).
Implements evidence for policy items **R-08**, **C-06** and **C-08** in
[ADMIN-IDENTITY-POLICY.md](ADMIN-IDENTITY-POLICY.md).

**Status:** specified, not shipped. Does not change the Gatekeeper runtimes, SMTP transport semantics,
or the certified CoSign / MFA behaviour.

Goal: replace "I think recovery still works" with "confirmed N days ago", with three rules:

1. **Verification on demand.** Draco never sends verification e-mails on its own. The dashboard shows
   how old each confirmation is; the administrator decides when to verify.
2. **A code, never a link.** Verification mail carries a short code that is typed back into the
   dashboard. Nobody is taught to click links in mail they did not expect.
3. **Visible health.** Every identity shows its last verifiable check, and the overview shows which
   ones are ageing.

---

## 1. Verifying an identity

Beside each recovery slot, the second administrator (CoSign) and the site mail (SMTP):

1. The administrator presses **[ Verify ]**. A confirmation shows the address the code goes to.
2. Draco sends a 6-digit code to that address, from the site's usual sender.
3. The administrator types the code into the dashboard, in the same session.
4. Draco records **last confirmation** (date, identity, operator) and the audit event.

A correct code proves that the mailbox exists, that mail from the site reaches it, and that the
operator can read it. SMTP itself only gets a delivery test (sent / refused), since it has no inbox.

### The message

- Subject and body are plain and short: the site's name and "Your verification code: 123456",
  valid for 15 minutes, plus "If you did not ask for it, ignore this message".
- No link, no mention of recovery, CoSign, MFA or administrators: a third party reading the mailbox
  learns only that the site sent a code.
- It is expected: it only ever arrives seconds after the operator pressed [ Verify ].

## 2. Dashboard

### Per identity

```
Recovery #1 · r***@example.net
Last confirmation:   2026-11-09 08:16 (7 days ago)
Status: ✓ Operational
[ Verify ]
```

Same pattern for **Second administrator (CoSign)**, and **Site mail (SMTP)** with its delivery test.

### Overview card — Security health

| State | Meaning |
| --- | --- |
| Green — Operational | Confirmed within 30 days |
| Yellow — Review recommended | 30–90 days |
| Red — Expired | More than 90 days |
| Grey — Never verified | No evidence |

The card lists the identities that are ageing, for example "Recovery #2: last verification 86 days
ago — review recommended", and links to the screen with the [ Verify ] buttons. A reminder may also
appear in the WordPress dashboard; it never sends mail.

---

## 3. SSDD — Single Source of Dependency Detection

The question is not "are the domains different?" but "do these mailboxes depend on the same
provider?". Two addresses on one domain share a provider, and two different domains often do too
(`empresa.com` and `empresa.net` may both point to the same mail service).

For Admin A, Admin B and every recovery slot, Draco:

1. takes the domain of the address;
2. looks up its **MX** records (DNS, cached for a day);
3. groups the MX hosts by provider: their registrable domain (`aspmx.l.google.com` → `google.com`,
   `mx1.hostinger.com` → `hostinger.com`), with a short table for providers whose MX hosts use
   several domains.

| Pattern | Result |
| --- | --- |
| Every identity on one provider | ⚠ Single-source dependency |
| A, B and recovery spread over at least two providers | ✓ Distributed dependencies |
| MX lookup failed | Unknown (not a warning) |

Detection is advisory: it never blocks a login and it never names a provider as better or worse.

---

## 4. Abuse controls

| Control | Rule |
| --- | --- |
| Rate limit | At most 1 code per identity per 24 h, and 5 per site per day |
| Explicit confirm | A confirmation showing the address before sending |
| Code | 6 digits, 15 minutes, 5 attempts, one use, stored only as a hash |
| Same session | The code is only accepted in the session that asked for it |
| Audit | `verification_sent`, `verification_confirmed`, `verification_expired`, `verification_failed` |
| Enumeration | The operator always sees "Code sent"; the real delivery outcome goes to the internal log |

---

## 5. Policy mapping

| Policy | Product evidence when shipped |
| --- | --- |
| R-08 recovery maintenance | Last confirmation per identity, with its age on the dashboard |
| C-06 recovery / approval health | Per-identity last confirmation by code |
| C-07 MFA continuity | Operator review cadence (process); optional later hooks |
| C-08 SSDD | Provider grouping by MX, shown as an advisory warning |

---

## 6. Out of scope

- Changing the CoSign / MFA / Trusted Device invariants
- The Gatekeeper runtimes
- Requiring several people (two identities remain enough)
- Sending verification mail automatically or on a schedule
- Endorsing a specific mail or authenticator vendor
