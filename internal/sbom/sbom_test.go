package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The test binary is a Go program: its SBOM must list the Go toolchain and
// carry the file's own hash.
func TestGenerateGoBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	bom, err := Generate(exe)
	if err != nil {
		t.Fatal(err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.Metadata.Component == nil {
		t.Fatalf("format %q, root %v", bom.BOMFormat, bom.Metadata.Component)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	var got string
	for _, h := range bom.Metadata.Component.Hashes {
		if h.Alg == "SHA-256" {
			got = h.Content
		}
	}
	if got != want {
		t.Errorf("root SHA-256 = %q, want %q", got, want)
	}
	stdlib := false
	for _, c := range bom.Components {
		stdlib = stdlib || strings.HasPrefix(c.PURL, "pkg:golang/stdlib@")
	}
	if !stdlib {
		t.Errorf("no pkg:golang/stdlib component among %d", len(bom.Components))
	}
}

func TestGenerateMissing(t *testing.T) {
	if _, err := Generate("/nonexistent/binary"); err == nil {
		t.Error("Generate of a missing file succeeded")
	}
}
