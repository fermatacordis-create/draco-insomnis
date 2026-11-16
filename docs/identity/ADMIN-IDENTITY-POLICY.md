# Administrative Identity Management and CoSign

Operational hardening policy for WordPress sites using Draco Insomnis CoSign.
Companion to [CERTIFICATION-0.1.32-ui16.md](CERTIFICATION-0.1.32-ui16.md).

Normative language: **MUST** / **SHOULD** / **MAY** follow RFC 2119 sense within this document.
Product certification (**C-01**…**C-05**) is mandatory for the shipped model. Items marked **SHOULD**
are recommended operational practice; **C-06** and Health Checks / SSDD describe the target evidence
model (see [TRUST-HEALTH.md](TRUST-HEALTH.md) for the planned product surface).

This policy improves resistance to enumeration, targeted phishing, abandoned recovery accounts and
accidental exposure of privileged mailboxes without imposing organisational complexity on small sites.

---

## 1. Purpose

Minimum expectations for administrative identities protected by CoSign:

1. Reduce risk from compromise of a single administrative identity.
2. Improve traceability of privileged logins (`auth_id`).
3. Limit public exposure of administrative credentials and mailboxes.
4. Keep correct attribution of actions after login (always Admin A).
5. Keep recovery and approval identities **verifiably usable**, not merely configured.

## 2. Principles

### P-01. Separation of identities

When CoSign is enabled, login requires two **distinct administrative identities**:

| Role | Name | Purpose |
| --- | --- | --- |
| Operational | Admin A | Receives the final session; daily work |
| Approval | Admin B | Co-signs only; does not own the session |

Certification requires **two identities**, not necessarily two people. One operator may hold both
accounts with separate passwords, MFA and recovery.

### P-02. Single attribution

After authentication, all content and functional audit trail remain attributed to **Admin A**.
CoSign does not change authorship or CMS attribution.

### P-03. Minimal exposure

Where possible, Admin B stays off the public surface of the site (no posts, no public contact role,
no marketing lists).

### P-04. Evidence over assumption

Security posture for recovery and approval SHOULD be stated as:

> Verified correctly N days ago

not:

> I believe that account still works

### P-05. Admin B never obtains a session

Admin B approves; it never becomes the operational user. Whatever happens during the flow, the only
session that can result is A's:

```
Password A + Password B + CoSign + (MFA A | Trusted Device A)  →  Session A
```

Never `Session B`. This keeps operation and audit simple: there is one person at work (A) and one
approval on record (B), and B's credentials alone open nothing.

### Invariant

**Trust Device ≠ Trusted Login**

Password A, Password B and CoSign remain mandatory when CoSign is on. Only the MFA e-mail code may
be omitted on a trusted device.

---

## 3. Policy for Admin B

Treat Admin B as an **Approval Account** / **Emergency Administrative Identity**.

### Allowed

- CoSign approval
- Administrative login for that purpose
- Access recovery
- Exceptional / break-glass operations
- Backup administrative account

### Not recommended

- Publishing posts or pages as routine work
- Editorial management
- Public contact forms
- Customer support mailboxes
- Marketing / newsletters
- Billing
- Unrelated third-party registrations

The lower the exposure of B, the harder it is to enumerate, phish or reuse that identity by accident.

---

## 4. E-mail separation

### Principle

Do not reuse one mailbox for public site functions and privileged authentication.

### Recommended split

| Function | Example |
| --- | --- |
| Public contact | `contacto@empresa.com`, `hola@empresa.com` |
| Operational admin (A) | a personal, non-role address (`op-47@empresa.com`) |
| CoSign / recovery (B) | a non-guessable address used for nothing else (`vault-b7@empresa.com`) |

Use B’s address only for administrative access, MFA, recovery and CoSign — not forms, support,
billing, marketing or external SaaS sign-ups.

### Avoid predictable names

Do not use role names that attackers try first, such as `security@`, `admin@`, `webmaster@`,
`cosign@` or `recovery@` (several are standard public role addresses, RFC 2142), nor login names
like `security` or `admin`. The examples in this policy show principles, not names to copy: choose
names that cannot be guessed from the site.

### Anti-pattern

One address for WordPress login, forms, billing, support and newsletters maximizes phishing and
credential-stuffing exposure of the privileged mailbox.

### Provider diversity (SHOULD)

When viable, administrative identities SHOULD NOT concentrate trust in a single mailbox provider.

Example:

```
Admin A  →  user@provider-one.example
Admin B  →  user@provider-two.example
```

One person, two identities, two providers. The gain is reduced single-platform failure — not
endorsement of any vendor. Prefer modern MFA, documented account recovery and an active provider;
diversify when possible.

---

## 5. Example setups

### Small site (one person, two identities)

| | Admin A | Admin B |
| --- | --- | --- |
| Login | the operator's own login | a non-obvious login, not "security" or "admin" |
| E-mail | the operator's own address | a dedicated, non-guessable address (`vault-b7@…`) |
| MFA | Yes | Yes |
| Recovery | Up to 3 slots | Up to 3 slots |

Compatible with CoSign: two identities, one operator.

### Small business

- Public: `hola@` / `contacto@`
- Ops: a personal address of the operator
- CoSign: a dedicated, non-guessable address, listed nowhere

### Higher assurance

- Public contact only on public mailboxes
- Ops and CoSign never listed on the site
- Separate recovery slots on both A and B
- Distinct mail providers for A and B when practical (by their MX records, not just the domain)

---

## 6. R-08. Maintenance of recovery identities (SHOULD)

### Objective

Identities used for **Recovery**, **CoSign** and **backup administration** SHOULD NOT sit unused for
long periods. Many recovery failures are not intrusions: the account was abandoned, MFA was lost,
the phone number changed, the mailbox was locked, or mail stopped arriving — discovered only when
needed.

### Recommended checks

Periodically verify:

- Access to the account
- Mail reception
- MFA state
- Recovery methods
- Absence of locks or provider restrictions

### Recommended cadence

| Criticality | Frequency |
| --- | --- |
| Home / personal site | Monthly |
| Professional / SME | Fortnightly |
| Production / SaaS | Weekly |
| Critical environments | Weekly |

**Default recommendation for Draco operators: weekly.** Fast detection, low effort, avoids years of
silent abandonment.

### Verification on demand (SHOULD)

The cadence above is a **review reminder**, not a mailing schedule. The site SHOULD NOT send
verification mail on its own: unexpected messages fill mailboxes, end up in spam and, if they carry
links, teach people to click links they did not expect.

Instead:

- the dashboard shows, per identity, how long ago it was last verified, and warns when it ages
  (for example "Last verification 86 days ago — review recommended");
- the administrator decides when to verify, from the dashboard;
- verification sends a **short code** (never a link) that is typed back into the dashboard, which
  proves that the mailbox exists, that mail arrives and that the operator can read it;
- the message is plain ("Your verification code: …") and MUST NOT mention recovery, administration,
  MFA or CoSign.

The product design is in [TRUST-HEALTH.md](TRUST-HEALTH.md).

---

## 7. R-09. MFA rotation and continuity (SHOULD)

### Objective

MFA for Admin A, Admin B and recovery-related accounts SHOULD remain usable after phone change,
device loss, breakage, restore or migration.

### Recommendation

Prefer app-based MFA when available (any well-supported authenticator). Advantages: broad device
support, multilingual UX, documented vendor account recovery. This policy does **not** mandate a
specific vendor.

### Before changing device

Verify account access, MFA and recovery; record date, account and operator internally.

### Migration

1. Enrol MFA on the new device.
2. Confirm login, code generation and challenge acceptance.
3. Perform a controlled login (password + MFA; CoSign if applicable).
4. Confirm recovery still intact.
5. Retire the old device **only after** the new MFA path is validated.

### Review cadence

| Identity | Review |
| --- | --- |
| Admin A | Quarterly |
| Admin B | Quarterly |
| Recovery-related accounts | Quarterly |

Also review on: device change, operator change, account reset, security incident.

---

## 8. Threats, mitigations and verifiable controls

| Threat | Mitigation | Verifiable control | Evidence |
| --- | --- | --- | --- |
| Theft of A’s password | CoSign + MFA | Login needs B | `login:cosign_success` |
| Theft of B’s password | Session still of A | No session as B | `login:session` user = A |
| Credential stuffing | A + B + MFA | Incomplete without B | No `login:session` |
| Admin enumeration | Keep B dark | B unused publicly | User / author review |
| Leak of A’s e-mail | Separate CoSign mailbox | Distinct e-mails | User profiles |
| Phishing of A | CoSign still required | Fail without B | Failure audits |
| MFA error | Full rollback | No active session | `get_current_user_id() === 0` |
| CoSign timeout | Challenge discarded | No persistence | No `login:session` |
| Challenge replay | One-shot challenge | Reject reuse | Replay tests |
| Service account as cosigner | Explicit reject | Filter / app-password check | `COSIGNER_SERVICE_ACCOUNT` |
| Loss of one recovery address | Multi-slot recovery | Other slots remain | Recovery config |
| Loss of primary mailbox | Recovery alternate | Recoverable login | Recovery configured |
| Abandoned recovery / CoSign mailbox | R-08 verification on demand | Last confirmation by code | C-06 evidence |
| MFA device lost without migration | R-09 continuity | Controlled re-enrolment record | Operator log / future health UI |
| Single mail provider for all admins | Provider diversity | Distinct providers by MX for A/B/recovery | SSDD (planned) |

### Residual risks (accepted)

| Residual risk | Status |
| --- | --- |
| Simultaneous compromise of A and B | Accepted |
| Compromise of mail infrastructure | Accepted |
| Social engineering against both identities | Accepted |
| Loss of all recovery slots at once | Accepted |
| Compromise of an already-authenticated device of A | Accepted |

---

## 9. Certification and recommended controls

### Mandatory (certified with 0.1.32-ui16, reproducible at commit `9893697`)

| ID | Control | Evidence |
| --- | --- | --- |
| C-01 | A ≠ B; human cosigner | `test_service_account_cannot_cosign`, cosign success tests |
| C-02 | Shared `auth_id` across the flow | `login:cosign_success` → `login:mfa` → `login:session` |
| C-03 | Session safety on errors | `get_current_user_id() === 0`, `is_user_logged_in() === false`, no `login:session` |
| C-04 | Trust Device ≠ Trusted Login | CoSign still runs when MFA is skipped |
| C-05 | 1–3 recovery e-mails | Recovery UI + legacy migration + slot lookup |

### Recommended (operational + planned product evidence)

| ID | Control | Evidence |
| --- | --- | --- |
| C-06 | Recovery / approval health check | Last confirmation by code per identity, on demand |
| C-07 | MFA continuity (R-09) | Periodic review; re-validation after device change |
| C-08 | SSDD — single-source dependency detection | Dashboard warning when A, B and recovery share one provider (grouped by MX) |

C-06…C-08 are **policy targets**. Product UI and audit endpoints for Health Checks / SSDD are specified
in [TRUST-HEALTH.md](TRUST-HEALTH.md) and are not required for ui16 certification.

---

## 10. Closing statement

The certification of CoSign in **0.1.32-ui16** verifies identity separation, `auth_id` traceability,
absence of partial sessions, and consistent MFA / Recovery behaviour.

Keeping an approval identity (Admin B) with near-zero public surface — ideally a dedicated mailbox —
does not replace MFA, CoSign, Recovery or Account Lock. Combined with **R-08** (keep recovery usable),
**R-09** (keep MFA migratable) and **provider diversity**, it reduces operational single points of
failure without requiring multiple people.

CoSign security does not require multiple humans. One operator with independent administrative
identities, MFA, recovery and differentiated mail providers already gains substantial resilience in
the administrative trust chain.
