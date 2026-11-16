# Certification — Draco Insomnis 0.1.32-ui16 (identity layer)

| Field | Value |
| --- | --- |
| Product | Draco Insomnis |
| Canary | `0.1.32-ui16` |
| Environment | sant-francesc |
| Scope | WordPress identity layer (Recovery, CoSign, MFA, Trusted Device, audit) |
| Status | **CERTIFIED — reproducible** (canary checks plus CI) |
| Commit | [`9893697`](https://github.com/fermatacordis-create/draco-insomnis/commit/989369777dbd4f2aa04b95b0f1d9f4e8ed970a08) (`989369777dbd4f2aa04b95b0f1d9f4e8ed970a08`), merge of #65 into `main` |
| CI | [run 43939337306](https://github.com/fermatacordis-create/draco-insomnis/actions/runs/43939337306): green, including the integration tests on WordPress 6.5 and latest and the WordPress.org Plugin Check |

Anyone can check what was certified: that commit, and the CI run that tested it.

### What the reproducible run found

On a clean WordPress, the CI exposed problems the canary site had hidden (it had MFA on when the plugin
loaded). They were fixed before the merge; the product's behaviour did not change:

- three CoSign tests were wrong: two only passed with MFA already on, and one used a helper that
  does not exist in that kind of test; a fourth checked the whole file instead of the CoSign gate;
- the WordPress.org Plugin Check asked for the user agent to be sanitized everywhere CoSign and MFA
  read it, and for a translators comment.

## Executive summary

The ui13 → ui16 series completes the identity work started with multi-slot recovery and administrator co-signature.

Certified outcomes:

1. Up to three verified recovery e-mails (legacy migration included).
2. Optional second-administrator CoSign before MFA.
3. Full audit correlation through a shared `auth_id`.
4. Trusted devices that omit only the MFA code — never CoSign.
5. Architecture preserved: WordPress = identity; Gatekeeper runtimes = access protection.
6. No partial sessions on any error path.

## Certified authentication model

### Standard flow

```
Password A → CoSign B → MFA A → Session A
```

### Trusted device flow

```
Password A → CoSign B → Trusted Device → Session A
```

### Invariant

**Trust Device ≠ Trusted Login**

| Step | Required |
| --- | --- |
| Password A | Mandatory |
| Password B | Mandatory (when CoSign is on) |
| CoSign | Mandatory (when CoSign is on) |
| MFA code | Optional if the device is trusted |

Resulting model:

```
Password A + Password B + CoSign + (MFA A | Trusted Device A) = Session A
```

The session always belongs to **A**. B only approves.

## Audit chain

### Normal login

```
login:cosign_success → auth_id → login:mfa → auth_id → login:session
```

### Trusted device

```
login:cosign_success → auth_id → login:session
```

`login:mfa` is intentionally absent; the same `auth_id` still links the events that exist.
Failures (`login:cosign_failure`) preserve the challenge `auth_id` for correlation.

## Certification checklist

### Recovery

| Check | Result |
| --- | --- |
| Legacy migration of `_draco_recovery_email` | PASS |
| Up to 3 recovery e-mails | PASS |
| Duplicates / primary address rejected | PASS |
| Lookup by any slot | PASS |
| MFA / password-reset compatible | PASS |

### CoSign

| Check | Result |
| --- | --- |
| Enable / disable from settings | PASS |
| Second administrator required | PASS |
| A ≠ B | PASS |
| Cosigner must be administrator | PASS |
| Account Lock approval when lock is on | PASS |
| Service accounts rejected (`draco_insomnis_cosign_service_account`) | PASS |
| Application passwords rejected | PASS |
| Challenge timeout | PASS |
| One-shot / replay protection | PASS |

### MFA & Trusted Device

| Check | Result |
| --- | --- |
| MFA runs after CoSign | PASS |
| Trust Device skips only the code | PASS |
| Trust Device does not skip CoSign | PASS |

### Audit

| Check | Result |
| --- | --- |
| `login:cosign_success` / `failure` / `mfa` / `session` | PASS |
| Shared `auth_id` on success | PASS |
| `auth_id` preserved on failure | PASS |

### Session safety

| Check | Result |
| --- | --- |
| No session after CoSign failure | PASS |
| No session after MFA failure | PASS |
| No session after timeout | PASS |
| No session after service-account rejection | PASS |
| No `login:session` on error paths | PASS |
| `get_current_user_id() === 0` on error paths | PASS |
| `is_user_logged_in() === false` on error paths | PASS |

### UI & localisation

| Check | Result |
| --- | --- |
| Recovery multi-slot UI | PASS |
| Overview “Two-step login” | PASS |
| Trusted Device wording (Admin + Overview) | PASS |
| `es_ES` | PASS |

### Architecture boundaries

| Check | Result |
| --- | --- |
| Identity = WordPress | PASS |
| Gatekeeper runtimes unchanged | PASS |
| SMTP transport unchanged by the identity layer | PASS |
| Base MFA semantics unchanged | PASS |

The site-mail settings screen (SMTP presets by country) and the optional microphone exception in
`Permissions-Policy` were developed at the same time but are separate changes, reviewed in their own
pull requests; they are not part of this certification.

## Certified test suite (`tests/integration/CoSignTest.php`)

- `test_auth_id_links_cosign_mfa_session`
- `test_auth_id_links_cosign_session_when_trusted`
- `test_session_event_contains_same_auth_id`
- `test_service_account_cannot_cosign`
- `test_trusted_device_skips_only_mfa`
- `test_cosign_failure_preserves_auth_id`
- `test_cosign_timeout_has_no_session`
- `test_mfa_failure_rolls_back_session`

Session-safety assertions on every error path:

```php
$this->assertSame(0, get_current_user_id());
$this->assertFalse(is_user_logged_in());
// and no login:session event
```

## Release notes — 0.1.32-ui16

### New / completed capabilities

- **Recovery multi-slot** — up to three verified recovery addresses; automatic legacy migration.
- **Administrator CoSign** — optional second-admin approval before MFA; session always of A.
- **`auth_id` correlation** — links `login:cosign_*`, `login:mfa`, and `login:session`.
- **Trusted devices clarified** — omit MFA code only; never CoSign, Account Lock, or password checks.
- **Overview** — Recovery / second-admin approval / trusted devices, with explicit Trust ≠ Trusted Login copy.

### Unchanged

SMTP transport, Firewall, Gatekeeper, and all non-WordPress runtimes (Go, Node, Java, .NET, Python, Rust, …).

## Verdict

| Area | Status |
| --- | --- |
| Recovery multi-slot | PASS (canary + CI) |
| Administrator CoSign | PASS (canary + CI) |
| Auth correlation | PASS (canary + CI) |
| Failure correlation | PASS (canary + CI) |
| Session safety | PASS (canary + CI) |
| Trusted Device model | PASS (canary + CI) |
| Architecture boundaries | PRESERVED |

**0.1.32-ui16 identity layer: PASS, reproducible at commit `9893697` with a green CI.**

Operational hardening for Admin A / Admin B (including **R-08** recovery maintenance with verification on
demand, **R-09** MFA continuity, provider diversity by MX, and planned **C-06** / SSDD health evidence) is documented in
[ADMIN-IDENTITY-POLICY.md](ADMIN-IDENTITY-POLICY.md) and [TRUST-HEALTH.md](TRUST-HEALTH.md).
