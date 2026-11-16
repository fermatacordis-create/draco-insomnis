# Security policy

Draco Insomnis is a security plugin, so a flaw in it can put the sites that trust it at risk.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub:
**Security → Report a vulnerability** on this repository.

Include what you found, how to reproduce it and which version you tested. We will confirm receipt,
agree on a date with you and credit you in the release notes unless you prefer otherwise.

## Verifying a release

Every release since 0.1.24 is built and signed by GitHub Actions from the tagged commit, with no key stored anywhere (Sigstore keyless signing):

```sh
# 1. The file was built by this repository's release workflow (GitHub build provenance):
gh attestation verify draco-insomnis-wordpress-X.Y.Z.zip -R fermatacordis-create/draco-insomnis

# 2. The checksums are the ones the workflow signed, and the file matches them:
cosign verify-blob --bundle SHA256SUMS.txt.sigstore.json \
  --certificate-identity "https://github.com/fermatacordis-create/draco-insomnis/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS.txt
sha256sum -c --ignore-missing SHA256SUMS.txt

# 3. The Docker add-on:
cosign verify ghcr.io/fermatacordis-create/draco-insomnis:X.Y.Z \
  --certificate-identity-regexp '^https://github.com/fermatacordis-create/draco-insomnis/.github/workflows/release.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each release also carries a CycloneDX 1.6 SBOM (`draco-insomnis-vX.Y.Z.cdx.json`), written by
`bin/build-sbom.php`, validated against the schema and attested by GitHub. Draco ships no
third-party code, so instead of a scanner's near-empty list it records:

- every package of the release, with its SHA-256 and SHA-512, its package URL (Composer, npm, deb,
  rpm, OCI) and what it runs on;
- the shared engines (`src/Core`) file by file, and which packages carry them;
- the Docker add-on by digest, and its base image;
- the country data (DB-IP Lite, CC BY 4.0), which is downloaded at run time and is in no package;
- every outside service Draco can talk to (Have I Been Pwned, rdap.org, the country list, your own
  CrowdSec): when, and exactly what it sends. None is used until the site's owner switches it on.

```
gh attestation verify SHA256SUMS.txt -R fermatacordis-create/draco-insomnis --predicate-type https://cyclonedx.org/bom
```

## Supported versions

Only the latest released version receives security fixes.

## WordPress identity (CoSign, MFA, recovery)

On WordPress, privileged login may use second-administrator co-sign, e-mail MFA and multi-slot
recovery. The internal canary certification of that model (`0.1.32-ui16`, reproducible certification pending) and the operational policy (Admin A/B,
recovery maintenance **R-08**, MFA continuity **R-09**, planned Health Checks / SSDD) are in
[`docs/identity/`](docs/identity/).

Invariant: **Trust Device ≠ Trusted Login** — a trusted device skips only the MFA code, never
CoSign or password validation. Prefer evidence (“verified N days ago”) over unused recovery accounts.

## Scope

The plugin only defends the site it runs on. It never sends anything to an attacker's machine,
and contributions that do (counter-attacks, scanning, payloads) will not be accepted.
