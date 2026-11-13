package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeRuleFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLoadRulesOfflineSupportsAllFormats(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, filepath.Join(dir, "a.yml"), "rules:\n- id: yml-rule\n  name: YAML\n  pattern: 'AKIA[0-9A-Z]{16}'\n")
	writeRuleFile(t, filepath.Join(dir, "b.toml"), "[[rules]]\ndescription = \"TOML\"\nid = \"toml-rule\"\nregex = '''AKIA[0-9A-Z]{16}'''\n")
	writeRuleFile(t, filepath.Join(dir, "c.txt"), "# comment\nAKIA[0-9A-Z]{16}\n")

	rules, err := LoadRulesOffline(dir)
	if err != nil {
		t.Fatalf("expected successful load, got %v", err)
	}
	ids := map[string]bool{}
	for _, rule := range rules {
		ids[rule.ID] = true
		if rule.Pattern == nil {
			t.Errorf("rule %s has nil compiled pattern", rule.ID)
		}
	}
	for _, want := range []string{"yml-rule", "toml-rule", "Rule-1"} {
		if !ids[want] {
			t.Errorf("missing expected rule id %q, have %v", want, ids)
		}
	}
}

func TestLoadRulesOfflineFailsOnMalformedYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yml")
	writeRuleFile(t, path, "rules:\n- id: bad\n  pattern: '[a-z'\n")
	if _, err := LoadRulesOffline(path); err == nil {
		t.Fatal("expected error for uncompilable YAML regex")
	}
}

func TestLoadRulesOfflineFailsOnMalformedTOML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.toml")
	writeRuleFile(t, path, "[[rules]]\nid = \"bad\"\nregex = \"[\"\n")
	if _, err := LoadRulesOffline(path); err == nil {
		t.Fatal("expected error for uncompilable TOML regex")
	}
}

func TestLoadRulesOfflineFailsOnMalformedTextLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.txt")
	writeRuleFile(t, path, "AKIA[0-9A-Z]{16}\n(\n")
	if _, err := LoadRulesOffline(path); err == nil {
		t.Fatal("expected error for invalid text regex")
	}
}

func TestLoadRulesOfflineFailsOnRuleWithoutID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "noid.yml")
	writeRuleFile(t, path, "rules:\n- name: no id\n  pattern: 'abc'\n")
	if _, err := LoadRulesOffline(path); err == nil {
		t.Fatal("expected error for YAML rule without id")
	}
}

func TestLoadRulesOfflineFailsOnUnsupportedExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.log")
	writeRuleFile(t, path, "whatever\n")
	if _, err := LoadRulesOffline(path); err == nil {
		t.Fatal("expected error for unsupported rules file extension")
	}
}

func TestLoadRulesOfflineFailsOnMissingPath(t *testing.T) {
	if _, err := LoadRulesOffline(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing rules path")
	}
}

func TestLoadRulesOfflineFailsOnEmptyDirectory(t *testing.T) {
	if _, err := LoadRulesOffline(t.TempDir()); err == nil {
		t.Fatal("expected error for rules directory with no rules")
	}
}

func TestLoadRulesOfflineFailsOnEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.txt")
	writeRuleFile(t, path, "# only a comment\n\n")
	if _, err := LoadRulesOffline(path); err == nil {
		t.Fatal("expected error for rules file with no loadable rules")
	}
}

func TestLoadRulesOfflineSkipsLicense(t *testing.T) {
	dir := t.TempDir()
	writeRuleFile(t, filepath.Join(dir, "LICENSE"), "copyright text\n")
	writeRuleFile(t, filepath.Join(dir, "a.yml"), "rules:\n- id: ok\n  pattern: 'abc'\n")
	rules, err := LoadRulesOffline(dir)
	if err != nil {
		t.Fatalf("LICENSE should be skipped, got %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "ok" {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}
