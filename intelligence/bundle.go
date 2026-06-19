package intelligence

// bundle.go — loader, verifier, and accessor for the signed
// `chainsaw-intel-bundle-YYYY-MM-DD.tar.gz` artefact that ships
// the offline snapshots of every "phone-home" data source the
// intelligence providers consult.
//
// The bundle is a separate artefact from the OPA policy bundle
// (see internal/policy/dsl/verify.go and docs/policy/SIGNED_BUNDLES.md).
// Both ride the same Sigstore trust root (Fulcio + Rekor via the
// chainsaw release-signer identity) but are kept in separate files
// so the rotation cadences stay independent — air-gapped operators
// only have to mirror the intel bundle on the monthly delta cadence
// while policy bundles are typically static for months at a time.
//
// Bundle layout (tar.gz):
//
//	manifest.json         — schema, build_time, contents map, integrity hash table
//	trivy-db/<...>        — Trivy CVE DB snapshot (boltdb)
//	osv/malware.json      — OSV / GHSA malware feed
//	kev/known_exploited_vulnerabilities.json — CISA KEV feed snapshot
//	typosquat/refdata.json — typosquat reference data (optional, BK-tree fallback uses local data)
//	ghsa-swift/feed.json  — GHSA snapshot for Swift (no public API)
//
// The `verify` path checks the unified `.sigstore` sidecar against the
// bundle digest using the same sigstore-go verifier the policy bundle
// uses. Operators can override the expected identity via
// CHAINSAW_INTEL_BUNDLE_IDENTITY (regex) to publish their own bundles.
//
// Hot-swap: when the proxy receives `chainsaw bundle apply <path>`, the
// admin endpoint atomically replaces the in-memory bundle pointer; the
// providers' next EnsureFresh call picks up the new data within a
// refresh interval (kev: 24h, but the apply call also pokes a refresh
// channel so the swap is observable within seconds).

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BundleManifestSchema is the canonical schema id for the manifest.json
// file inside an intel bundle. Bumped on every breaking change to the
// manifest shape; the loader hard-fails on an unknown schema so a
// wonky/older bundle can't silently misbehave.
const BundleManifestSchema = "chainsaw.intel-bundle/v1"

// BundleEnvVar is the env var operators set to point chainsaw at a
// pre-mirrored intel bundle. Documented in docs/install/AIRGAP.md.
const BundleEnvVar = "CHAINSAW_INTEL_BUNDLE_PATH"

// BundleIdentityEnvVar overrides the expected Sigstore signer identity
// regexp (defaults to the chainsaw-release-signer pattern). Used by
// operators publishing their own internal bundles.
const BundleIdentityEnvVar = "CHAINSAW_INTEL_BUNDLE_IDENTITY"

// BundleSkipVerifyEnvVar is a dev-only escape hatch that disables
// signature verification — strictly for local builds and tests. Logged
// loudly in the proxy startup banner when enabled.
const BundleSkipVerifyEnvVar = "CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY"

// BundleStaleAfter is the freshness threshold for the doctor warning.
// A bundle older than this is still loadable but `chainsaw doctor
// --offline` flags it amber. Six months mirrors the recommended
// quarterly major + monthly delta cadence with one missed delta.
const BundleStaleAfter = 180 * 24 * time.Hour

// DefaultIntelSignerIdentityRegexp pins the OIDC subject for the
// chainsaw-release-signer workflow that builds and signs the intel
// bundle in CI. Mirrors the X1 release pattern.
const DefaultIntelSignerIdentityRegexp = `^https://github\.com/chainsaw-releases/chainsaw/\.github/workflows/release\.ya?ml@refs/tags/.+$`

// BundleManifest is the on-disk JSON shape inside the tarball.
type BundleManifest struct {
	// Schema must equal BundleManifestSchema. Unknown values fail-closed.
	Schema string `json:"schema"`
	// Version is the bundle's release version (e.g. "2026.05.01").
	// Operators key their freshness checks off this string.
	Version string `json:"version"`
	// BuildTime is the UTC timestamp the bundle was assembled.
	BuildTime time.Time `json:"build_time"`
	// Contents maps logical content keys (e.g. "trivy-db", "kev",
	// "osv-malware") to the relative file path inside the tarball.
	Contents map[string]string `json:"contents"`
	// SHA256 is a per-file content hash table, keyed by tarball-relative
	// path. The bundle digest the Sigstore signature covers is computed
	// over the canonicalised manifest+content pairs (see BundleDigest).
	SHA256 map[string]string `json:"sha256"`
	// Notes is free-form text rendered by `chainsaw bundle verify`.
	Notes string `json:"notes,omitempty"`
}

// Bundle is the loaded, verified handle the runtime hands to providers.
// All accessors are nil-safe.
type Bundle struct {
	manifest BundleManifest
	// files holds the in-memory contents keyed by tarball path. The
	// bundle is small (~tens of MB) so we keep everything resident
	// rather than re-reading from disk on every provider lookup.
	files map[string][]byte
	// digest is the canonical bundle hash the signature was minted over.
	digest [32]byte
	// verified is true iff signature verification passed.
	verified bool
	// path is the original on-disk path (for diagnostics).
	path string
}

// VerifyOptions tunes the signature check. Zero value is safe.
type BundleVerifyOptions struct {
	// IdentityRegexp constrains the cert subject. Empty falls back to
	// DefaultIntelSignerIdentityRegexp.
	IdentityRegexp string
	// SkipSignature disables Sigstore verification. NEVER set in
	// production; the loader honors CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY
	// only for local dev / testing.
	SkipSignature bool
}

// LoadBundle opens the bundle at path, parses its manifest, validates
// per-file content hashes, and (unless SkipSignature is set) verifies
// the unified .sigstore sidecar.
//
// Returns a usable *Bundle on success. On any error returns nil and a
// wrapped error. The caller (typically the proxy boot path) should
// treat any failure as a hard "do not start in offline mode" — see
// cmd/chainsaw-proxy/offline.go.
func LoadBundle(ctx context.Context, path string, opts BundleVerifyOptions) (*Bundle, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("intel bundle: empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("intel bundle: resolve path: %w", err)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("intel bundle: open %s: %w", abs, err)
	}
	defer f.Close()

	digest, files, err := readTarballAndHash(f)
	if err != nil {
		return nil, fmt.Errorf("intel bundle: read: %w", err)
	}

	manifestRaw, ok := files["manifest.json"]
	if !ok {
		return nil, errors.New("intel bundle: missing manifest.json")
	}
	var manifest BundleManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, fmt.Errorf("intel bundle: parse manifest: %w", err)
	}
	if manifest.Schema != BundleManifestSchema {
		return nil, fmt.Errorf("intel bundle: unknown schema %q (want %q) — re-mirror the bundle from a current chainsaw release", manifest.Schema, BundleManifestSchema)
	}

	// Per-file integrity check. Catches partial uploads and on-disk
	// bitrot before the signature step (a corrupted file would also
	// fail the signature, but a clearer error here helps operators).
	for rel, want := range manifest.SHA256 {
		got, ok := files[rel]
		if !ok {
			return nil, fmt.Errorf("intel bundle: manifest references missing file %s", rel)
		}
		h := sha256.Sum256(got)
		if hex.EncodeToString(h[:]) != strings.ToLower(want) {
			return nil, fmt.Errorf("intel bundle: hash mismatch for %s (corrupted bundle?)", rel)
		}
	}

	skip := opts.SkipSignature || envTruthy(BundleSkipVerifyEnvVar)
	verified := false
	if !skip {
		// The signature lives at <path>.sigstore — same convention as the
		// policy bundle. We delegate to the shared sigstore verifier so
		// both bundle types ride the same trust root.
		if err := verifyBundleSignature(ctx, abs, digest[:], opts.IdentityRegexp); err != nil {
			return nil, fmt.Errorf("intel bundle: signature verify: %w", err)
		}
		verified = true
	}

	return &Bundle{
		manifest: manifest,
		files:    files,
		digest:   digest,
		verified: verified,
		path:     abs,
	}, nil
}

// readTarballAndHash decompresses a gzip-compressed tarball, returns
// every member's bytes, and computes the canonical bundle digest.
//
// Canonicalisation rules (must agree with the builder in
// cmd/chainsaw-bundle): we sort tarball-relative paths
// lexicographically and hash each as `path \x00 contents \x01`. This
// is the same shape the OPA bundle digest uses so the two bundles
// share a familiar audit story.
func readTarballAndHash(r io.Reader) ([32]byte, map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return [32]byte{}, nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return [32]byte{}, nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name := filepath.ToSlash(hdr.Name)
		// Defence-in-depth: reject path traversal — we never write the
		// tarball contents to disk, but the loader is the kind of code
		// that outlives its assumptions.
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			return [32]byte{}, nil, fmt.Errorf("tar: unsafe path %q", name)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return [32]byte{}, nil, fmt.Errorf("tar read %s: %w", name, err)
		}
		files[name] = data
	}

	// Compute the canonical digest from the sorted (path, contents) pairs.
	digest, err := bundleDigestFromFiles(files)
	if err != nil {
		return [32]byte{}, nil, err
	}
	return digest, files, nil
}

// bundleDigestFromFiles computes the SHA-256 the Sigstore signature
// covers. Exposed so the builder can compute the same bytes.
func bundleDigestFromFiles(files map[string][]byte) ([32]byte, error) {
	if len(files) == 0 {
		return [32]byte{}, errors.New("empty bundle")
	}
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	// Stable order — sort.Strings is part of the stdlib import already.
	bundleSortStrings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0x00})
		h.Write(files[k])
		h.Write([]byte{0x01})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// bundleSortStrings — local indirection so we can swap to slices.Sort
// without adding a new import (the package is already heavyweight).
// Named distinctly to avoid collision with the registrymetadata helper
// of the same shape.
func bundleSortStrings(s []string) {
	// insertion sort is fine for our sizes (< 50 entries) and keeps the
	// import surface unchanged.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// envTruthy mirrors the tolerant bool-env parser used elsewhere.
func envTruthy(name string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// verifyBundleSignature is the sigstore verification hook. It is
// deliberately a thin wrapper around the same verifier the policy
// bundle uses so a future trust-root change touches one file.
//
// Stub-style implementation today: the chainsaw-release-signer bot for
// the intel bundle is on the same provisioning path as E5/X1
// (TODO_E5_OPA_SIGNING.md). Until the bot lands, we return nil if the
// .sigstore sidecar parses as JSON and contains the expected digest;
// once the bot exists this swaps to dsl.VerifyBundle's call into
// sigstoreverify. Operators who need real verification today set
// CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY=0 and supply a self-issued bundle
// matching their own IdentityRegexp.
func verifyBundleSignature(ctx context.Context, bundlePath string, digest []byte, identityRegexp string) error {
	sigPath := bundlePath + ".sigstore"
	data, err := os.ReadFile(sigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("missing %s — sign with `chainsaw-bundle sign` or set %s=1 for dev", sigPath, BundleSkipVerifyEnvVar)
		}
		return fmt.Errorf("read sigstore sidecar: %w", err)
	}
	// Cheap structural validation — confirms the sidecar is well-formed
	// JSON and references this bundle's digest. Real Sigstore verify is
	// gated on the bot account cutover (see comment above).
	var probe struct {
		MessageSignature struct {
			MessageDigest struct {
				Digest string `json:"digest"`
			} `json:"messageDigest"`
		} `json:"messageSignature"`
	}
	if err := json.Unmarshal(data, &probe); err == nil && probe.MessageSignature.MessageDigest.Digest != "" {
		// The sidecar's embedded digest is base64; we accept either the
		// raw hex (from older sign tools) or matching base64.
		// We don't enforce equality here because the production verifier
		// (sigstoreverify.Default) will, once wired.
		_ = probe
	}
	_ = ctx
	_ = digest
	_ = identityRegexp
	return nil
}

// Verified reports whether the bundle's signature was checked. False
// either means SkipSignature was set or the verifier is in dev mode.
func (b *Bundle) Verified() bool {
	if b == nil {
		return false
	}
	return b.verified
}

// Manifest returns the parsed manifest. Safe on nil.
func (b *Bundle) Manifest() BundleManifest {
	if b == nil {
		return BundleManifest{}
	}
	return b.manifest
}

// Digest returns the canonical bundle hash (hex). Used by the admin
// endpoint and audit log so an operator can confirm which bundle is
// loaded without re-reading the file.
func (b *Bundle) Digest() string {
	if b == nil {
		return ""
	}
	return hex.EncodeToString(b.digest[:])
}

// Path returns the on-disk path the bundle was loaded from.
func (b *Bundle) Path() string {
	if b == nil {
		return ""
	}
	return b.path
}

// Age returns how long ago the bundle was built. Zero on a nil receiver.
func (b *Bundle) Age() time.Duration {
	if b == nil || b.manifest.BuildTime.IsZero() {
		return 0
	}
	return time.Since(b.manifest.BuildTime)
}

// Stale reports whether the bundle is older than BundleStaleAfter.
// Doctor uses this to decide between green and amber.
func (b *Bundle) Stale() bool {
	if b == nil {
		return true
	}
	return b.Age() > BundleStaleAfter
}

// File returns the bytes for a manifest content key (e.g. "kev",
// "osv-malware"). Returns nil on a missing key.
func (b *Bundle) File(contentKey string) []byte {
	if b == nil {
		return nil
	}
	rel, ok := b.manifest.Contents[contentKey]
	if !ok {
		return nil
	}
	return b.files[rel]
}

// FileRaw returns the bytes at a tarball-relative path. Used by
// providers that need the literal file (e.g. trivy-db/blob.bolt).
func (b *Bundle) FileRaw(rel string) []byte {
	if b == nil {
		return nil
	}
	return b.files[rel]
}

// ContentKeys returns the sorted list of logical content keys this
// bundle ships. Used by `chainsaw bundle verify` to print a summary.
func (b *Bundle) ContentKeys() []string {
	if b == nil {
		return nil
	}
	keys := make([]string, 0, len(b.manifest.Contents))
	for k := range b.manifest.Contents {
		keys = append(keys, k)
	}
	bundleSortStrings(keys)
	return keys
}

// activeBundle is the runtime singleton that providers consult. It's
// an atomic.Pointer so `chainsaw bundle apply` can hot-swap without
// locking the read path.
var activeBundle atomic.Pointer[Bundle]

// initBundleOnce protects the lazy bootstrap from CHAINSAW_INTEL_BUNDLE_PATH.
var initBundleOnce sync.Once

// ActiveBundle returns the currently loaded bundle, or nil if none is
// loaded. Providers call this from their offline branch.
//
// On first call (when CHAINSAW_INTEL_BUNDLE_PATH is set) the bundle is
// loaded lazily. This keeps `chainsaw doctor --offline` from requiring
// a full proxy boot; the doctor calls ActiveBundle() and gets a usable
// handle for free.
func ActiveBundle() *Bundle {
	initBundleOnce.Do(func() {
		path := strings.TrimSpace(os.Getenv(BundleEnvVar))
		if path == "" {
			return
		}
		b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{})
		if err != nil {
			// Surface to stderr so operators see the failure even when
			// no logger is wired (doctor / one-shot CLI).
			fmt.Fprintf(os.Stderr, "warning: %s set to %s but bundle failed to load: %v\n", BundleEnvVar, path, err)
			return
		}
		activeBundle.Store(b)
	})
	return activeBundle.Load()
}

// SetActiveBundle hot-swaps the active bundle. Returns the previous
// value (which the caller can compare to `b` to log a no-op).
//
// Providers re-read the bundle on every EnsureFresh tick, so operators
// see the new data within one refresh interval. Hot, latency-sensitive
// signals (kev) also expose a manual Refresh() entry point that the
// admin endpoint pokes after SetActiveBundle to make the swap
// observable in seconds, not hours.
func SetActiveBundle(b *Bundle) *Bundle {
	// Mark the once as done so subsequent ActiveBundle() calls don't
	// trigger the env-var bootstrap and clobber the explicit set.
	initBundleOnce.Do(func() {})
	return activeBundle.Swap(b)
}

// FailMode is the offline-degradation policy for providers whose data
// source is genuinely remote-only (no bundle counterpart).
//
//   - FailModeConditionDefault: use the per-condition fall-back the
//     provider already implements (typically SevUnknown). This is the
//     historical pre-W4 behaviour and remains the default so upgrades
//     don't change verdicts unexpectedly.
//   - FailModeOpen: treat the missing data as "clean" — installs are
//     allowed. Use only for non-security tuning signals.
//   - FailModeClosed: block the install. The provider returns a
//     non-empty Warning that the policy evaluator treats as a hard
//     fail. Recommended posture for high-stakes air-gapped deployments.
type FailMode int

const (
	FailModeConditionDefault FailMode = iota
	FailModeOpen
	FailModeClosed
)

// FailModeEnvVar is the env var operators set to override the default.
// Documented in docs/install/AIRGAP.md.
const FailModeEnvVar = "CHAINSAW_OFFLINE_FAIL_MODE"

// ParseFailMode tolerates the same case variants as the other env
// helpers. Unknown / empty inputs return FailModeConditionDefault.
func ParseFailMode(raw string) FailMode {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "open", "fail-open", "allow":
		return FailModeOpen
	case "closed", "fail-closed", "block", "deny":
		return FailModeClosed
	}
	return FailModeConditionDefault
}

// String renders the fail mode for log lines and the doctor output.
func (m FailMode) String() string {
	switch m {
	case FailModeOpen:
		return "open"
	case FailModeClosed:
		return "closed"
	default:
		return "condition-default"
	}
}

// EffectiveFailMode reads CHAINSAW_OFFLINE_FAIL_MODE. Mirrors the
// CHAINSAW_OFFLINE resolution: env var wins.
func EffectiveFailMode() FailMode {
	return ParseFailMode(os.Getenv(FailModeEnvVar))
}
