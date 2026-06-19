package intelligence

// bundle_test.go — unit tests for the W4 intelligence bundle loader.
// Covers: round-trip build → load, schema rejection, hash mismatch
// detection, freshness logic, fail-mode parsing, and the active-bundle
// hot-swap accessor.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTestBundle builds a minimal-but-valid bundle to a temp path.
// Returns (bundlePath, sigstorePath). The .sigstore sidecar is the
// dev-mode placeholder our verifier accepts when SkipSignature is set.
func writeTestBundle(t *testing.T, contents map[string]string, buildTime time.Time, schemaOverride string) string {
	t.Helper()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "test-bundle.tar.gz")

	files := map[string][]byte{}
	contentMap := map[string]string{}
	hashes := map[string]string{}
	for key, payload := range contents {
		rel := key + "/data.json"
		data := []byte(payload)
		files[rel] = data
		contentMap[key] = rel
		h := sha256.Sum256(data)
		hashes[rel] = hex.EncodeToString(h[:])
	}

	schema := BundleManifestSchema
	if schemaOverride != "" {
		schema = schemaOverride
	}
	manifest := BundleManifest{
		Schema:    schema,
		Version:   "test-1.0",
		BuildTime: buildTime,
		Contents:  contentMap,
		SHA256:    hashes,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	files["manifest.json"] = manifestBytes

	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(data)),
			ModTime: buildTime,
		}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write data: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}

	// Empty placeholder sidecar — the dev-mode verifier accepts any
	// well-formed JSON file.
	if err := os.WriteFile(out+".sigstore", []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write sigstore: %v", err)
	}
	return out
}

func TestLoadBundle_RoundTrip(t *testing.T) {
	path := writeTestBundle(t,
		map[string]string{
			"kev":         `{"vulnerabilities":[]}`,
			"osv-malware": `[]`,
		},
		time.Now().UTC().Add(-time.Hour),
		"")

	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if got := b.Manifest().Version; got != "test-1.0" {
		t.Errorf("version: got %q want test-1.0", got)
	}
	if data := b.File("kev"); !bytes.Contains(data, []byte("vulnerabilities")) {
		t.Errorf("kev contents: got %q", data)
	}
	if b.Stale() {
		t.Errorf("fresh bundle reported stale")
	}
}

func TestLoadBundle_StaleWarn(t *testing.T) {
	path := writeTestBundle(t,
		map[string]string{"kev": `{}`},
		time.Now().UTC().Add(-2*BundleStaleAfter),
		"")
	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if !b.Stale() {
		t.Errorf("expected stale=true on aged bundle")
	}
}

func TestLoadBundle_RejectsUnknownSchema(t *testing.T) {
	path := writeTestBundle(t,
		map[string]string{"kev": `{}`},
		time.Now().UTC(),
		"chainsaw.intel-bundle/v999")
	_, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err == nil {
		t.Fatalf("expected schema rejection")
	}
}

func TestLoadBundle_DetectsHashMismatch(t *testing.T) {
	// Hand-roll a bundle with a manifest that lies about the contents.
	tmp := t.TempDir()
	out := filepath.Join(tmp, "bad.tar.gz")
	manifest := BundleManifest{
		Schema:    BundleManifestSchema,
		Version:   "bad",
		BuildTime: time.Now().UTC(),
		Contents:  map[string]string{"kev": "kev/data.json"},
		// Hash of literally zero bytes — won't match the actual file.
		SHA256: map[string]string{"kev/data.json": hex.EncodeToString(sha256.New().Sum(nil))},
	}
	mb, _ := json.Marshal(manifest)
	files := map[string][]byte{
		"manifest.json": mb,
		"kev/data.json": []byte("{}"),
	}
	f, _ := os.Create(out)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for n, d := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(d))})
		_, _ = tw.Write(d)
	}
	tw.Close()
	gz.Close()
	f.Close()
	_ = os.WriteFile(out+".sigstore", []byte("{}"), 0o644)
	_, err := LoadBundle(context.Background(), out, BundleVerifyOptions{SkipSignature: true})
	if err == nil {
		t.Fatalf("expected hash-mismatch error")
	}
}

func TestParseFailMode(t *testing.T) {
	cases := map[string]FailMode{
		"":                  FailModeConditionDefault,
		"condition-default": FailModeConditionDefault,
		"open":              FailModeOpen,
		"fail-open":         FailModeOpen,
		"closed":            FailModeClosed,
		"fail-closed":       FailModeClosed,
		"BLOCK":             FailModeClosed,
		"  open  ":          FailModeOpen,
		"garbage":           FailModeConditionDefault,
	}
	for in, want := range cases {
		if got := ParseFailMode(in); got != want {
			t.Errorf("ParseFailMode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSetActiveBundle_HotSwap(t *testing.T) {
	prev := activeBundle.Load()
	defer activeBundle.Store(prev)

	path := writeTestBundle(t,
		map[string]string{"kev": `{}`},
		time.Now().UTC(),
		"")
	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	SetActiveBundle(b)
	if got := ActiveBundle(); got != b {
		t.Errorf("ActiveBundle did not return the swapped bundle")
	}
}

func TestBundleNilSafety(t *testing.T) {
	var b *Bundle
	if b.Verified() || !b.Stale() || b.Digest() != "" || b.Path() != "" || b.Age() != 0 {
		t.Errorf("nil bundle accessors returned unexpected non-zero values")
	}
	if b.File("kev") != nil || b.FileRaw("x") != nil || len(b.ContentKeys()) != 0 {
		t.Errorf("nil bundle accessors returned non-nil data")
	}
}
