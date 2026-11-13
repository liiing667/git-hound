package app

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

func offlineTestFlags(t *testing.T, rules ...Rule) {
	t.Helper()
	flags := GetFlags()
	flags.TextRegexes = rules
	flags.Threads = 2
	flags.NoScoring = false
	flags.NoFiles = false
	flags.NoKeywords = false
	flags.FileExtensions = ""
	flags.Debug = false
}

func writeOfflineFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestScanOfflineDirectoryFindsRuleMatchWithStableLocation(t *testing.T) {
	root := t.TempDir()
	writeOfflineFile(t, root, filepath.Join("sub", "app.py"),
		"aws_key = \"AKIADEADBEEFDEADBEEF\"\nnothing here\n")

	offlineTestFlags(t, Rule{
		ID:      "test-aws",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	})

	findings, err := ScanOfflineDirectory(root)
	if err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.File != filepath.ToSlash(filepath.Join("sub", "app.py")) {
		t.Errorf("unexpected relative file: %s", finding.File)
	}
	if finding.Line != 1 || finding.Column != 12 {
		t.Errorf("unexpected location line=%d column=%d", finding.Line, finding.Column)
	}
	if finding.RuleID != "test-aws" || finding.Match != "AKIADEADBEEFDEADBEEF" {
		t.Errorf("unexpected finding: %+v", finding)
	}
}

func TestScanOfflineDirectoryDeterministicOrder(t *testing.T) {
	root := t.TempDir()
	writeOfflineFile(t, root, "b.txt", "AKIADEADBEEFDEADBEEF\nAKIADEADBEEFDEADBEEF\n")
	writeOfflineFile(t, root, "a.txt", "AKIADEADBEEFDEADBEEF\n")

	offlineTestFlags(t, Rule{
		ID:      "test-aws",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	})

	first, err := ScanOfflineDirectory(root)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	second, err := ScanOfflineDirectory(root)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("expected 3 findings on both runs, got %d and %d", len(first), len(second))
	}
	for i := range first {
		if !reflect.DeepEqual(first[i], second[i]) {
			t.Fatalf("non-deterministic output at index %d:\n%+v\n%+v", i, first[i], second[i])
		}
	}
	if first[0].File != "a.txt" || first[1].File != "b.txt" || first[2].Line != 2 {
		t.Fatalf("findings not sorted by file then line: %+v", first)
	}
}

func TestScanOfflineDirectorySkipsExcludedFoldersAndBinaries(t *testing.T) {
	root := t.TempDir()
	writeOfflineFile(t, root, filepath.Join("node_modules", "pkg", "x.txt"),
		"AKIADEADBEEFDEADBEEF\n")
	writeOfflineFile(t, root, filepath.Join(".git", "config"),
		"AKIADEADBEEFDEADBEEF\n")

	offlineTestFlags(t, Rule{
		ID:      "test-aws",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	})

	findings, err := ScanOfflineDirectory(root)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected skipped folders to produce no findings, got %+v", findings)
	}

	writeOfflineFile(t, root, "image.png", "AKIADEADBEEFDEADBEEF\n")
	writeOfflineFile(t, root, "blob.dat", "binary\x00\x00\x00AKIADEADBEEFDEADBEEF")
	findings, err = ScanOfflineDirectory(root)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected blacklisted extension and binary to be skipped, got %+v", findings)
	}
}

func TestScanOfflineDirectoryRejectsFileTarget(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	if err := os.WriteFile(file, []byte("x"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	offlineTestFlags(t)
	if _, err := ScanOfflineDirectory(file); err == nil {
		t.Fatal("expected error when scan target is a file")
	}
	if _, err := ScanOfflineDirectory(filepath.Join(root, "missing")); err == nil {
		t.Fatal("expected error when scan target does not exist")
	}
}

func TestScanOfflineLinesReportsBase64DecodedMatches(t *testing.T) {
	offlineTestFlags(t, Rule{
		ID:      "test-key",
		Pattern: regexp.MustCompile(`api_key = "[0-9a-z]{32}"`),
	})

	// echo -n 'api_key = "951bc382db9abad29c68634761dd6e19"' | base64
	lines := []string{`token="YXBpX2tleSA9ICI5NTFiYzM4MmRiOWFiYWQyOWM2ODYzNDc2MWRkNmUxOSI="`}
	findings := scanOfflineLines("encoded.txt", lines)

	var decoded *OfflineFinding
	for i := range findings {
		if findings[i].Base64 {
			decoded = &findings[i]
			break
		}
	}
	if decoded == nil {
		t.Fatalf("expected a base64-decoded finding, got %+v", findings)
	}
	if decoded.Line != 1 || decoded.RuleID != "test-key" {
		t.Errorf("unexpected decoded finding: %+v", decoded)
	}
	if !containsAttribute(decoded.Attributes, "base64") {
		t.Errorf("decoded finding missing base64 attribute: %+v", decoded.Attributes)
	}
}

func TestScanOfflineLinesAppliesSmartFiltering(t *testing.T) {
	offlineTestFlags(t, Rule{
		ID:             "test-smart",
		Pattern:        regexp.MustCompile(`secret=[a-z0-9]+`),
		SmartFiltering: true,
	})

	findings := scanOfflineLines("f.txt", []string{"secret=aaaaaaaaaaaaaaaa"})
	if len(findings) != 0 {
		t.Fatalf("expected low-entropy/repeated match to be filtered, got %+v", findings)
	}

	findings = scanOfflineLines("f.txt", []string{"secret=abcdef9182736450a1b2c3d4e5f60718"})
	if len(findings) != 1 {
		t.Fatalf("expected high-entropy match to pass smart filtering, got %+v", findings)
	}
}

func containsAttribute(attributes []string, want string) bool {
	for _, attribute := range attributes {
		if attribute == want {
			return true
		}
	}
	return false
}
