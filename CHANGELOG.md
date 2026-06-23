# Changelog

Notable changes to the Chainsaw open-core engine — the `chainsaw` CLI and the
decision libraries in this module (proxy, policy, intelligence, risk, typosquat,
malware, depgraph, SBOM, provenance). Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

A human-readable, product-wide view lives at <https://chain305.com/changelog/>.
Tagged releases (each with a published SHA-256 checksum) appear on the
[GitHub Releases](https://github.com/ZeeshanDarasa/chainsaw-core/releases) page
once the first signed release is cut.

## Unreleased

### Added
- Intel-bundle signature verification: always-on digest binding, plus opt-in
  full Sigstore authenticity (Fulcio + Rekor + OIDC issuer + signer-identity)
  behind `CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY` / `RequireAuthenticity`.
- `chainsaw bundle verify --strict` and `chainsaw doctor --offline` distinguish
  digest-bound integrity from full Sigstore authenticity.

### Changed
- Engine relicensed to **Apache-2.0**; builds standalone via
  `go install github.com/ZeeshanDarasa/chainsaw-core/cmd/chainsaw@latest`.

_Versioned entries begin with the first tagged release._
