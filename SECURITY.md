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

Each release also carries a CycloneDX SBOM (`draco-insomnis-vX.Y.Z.cdx.json`) listing every file of every package.

## Supported versions

Only the latest released version receives security fixes.

## Scope

The plugin only defends the site it runs on. It never sends anything to an attacker's machine,
and contributions that do (counter-attacks, scanning, payloads) will not be accepted.
