# Identity layer (WordPress)

Draco keeps **identity** on WordPress (passwords, CoSign, MFA, recovery, SMTP for codes).
Gatekeeper runtimes protect access elsewhere and are unchanged by this work.

| Document | Content |
| --- | --- |
| [CERTIFICATION-0.1.32-ui16.md](CERTIFICATION-0.1.32-ui16.md) | Certification (PASS), reproducible: commit `9893697` and its green CI run |
| [ADMIN-IDENTITY-POLICY.md](ADMIN-IDENTITY-POLICY.md) | Formal policy: A/B, R-08/R-09, C-01…C-08, threats |
| [TRUST-HEALTH.md](TRUST-HEALTH.md) | Planned health checks (verification on demand, by code) + SSDD by MX |

**Trust Device ≠ Trusted Login:** Password A + Password B + CoSign stay mandatory when CoSign is on;
only the MFA e-mail code may be omitted on a trusted device. Session is always A; B never obtains one.

**Evidence over assumption:** recovery and approval identities SHOULD be verified regularly (R-08),
on demand from the dashboard with a code, not left unused until an incident.
