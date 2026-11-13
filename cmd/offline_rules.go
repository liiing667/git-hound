package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v2"

	"github.com/tillson/git-hound/internal/app"
)

// LoadRulesOffline loads GitHound rules without any network dependency and
// fails closed: a malformed rule file or an uncompilable pattern is returned
// as an error instead of being silently skipped.
func LoadRulesOffline(path string) ([]app.Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("rules path %q: %w", path, err)
	}

	if info.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, fmt.Errorf("reading rules directory %q: %w", path, err)
		}

		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if !entry.IsDir() {
				names = append(names, entry.Name())
			}
		}
		sort.Strings(names)

		var allRules []app.Rule
		for _, name := range names {
			filePath := filepath.Join(path, name)
			rules, err := loadSingleRuleFile(filePath)
			if err != nil {
				return nil, err
			}
			allRules = append(allRules, rules...)
		}
		if len(allRules) == 0 {
			return nil, fmt.Errorf("rules path %q contains no loadable rule files", path)
		}
		return allRules, nil
	}

	rules, err := loadSingleRuleFile(path)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("rules file %q contains no loadable rules", path)
	}
	return rules, nil
}

// loadSingleRuleFile parses one YAML, TOML or plain-text rule file.
func loadSingleRuleFile(path string) ([]app.Rule, error) {
	baseName := filepath.Base(path)
	if baseName == "LICENSE" {
		return nil, nil
	}

	file, err := os.OpenFile(path, os.O_RDONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("opening rules file %q: %w", path, err)
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yml", ".yaml":
		return parseYAMLRules(path, file)
	case ".toml":
		return parseTOMLRules(path)
	case ".txt", "":
		return parseTextRules(path, file)
	default:
		return nil, fmt.Errorf("rules file %q has unsupported extension %q (supported: .yml, .yaml, .toml, .txt)", path, ext)
	}
}

func parseYAMLRules(path string, file *os.File) ([]app.Rule, error) {
	dec := yaml.NewDecoder(file)
	ruleConfig := app.RuleConfig{}
	if err := dec.Decode(&ruleConfig); err != nil {
		return nil, fmt.Errorf("parsing YAML rules file %q: %w", path, err)
	}
	if err := validateRules(path, ruleConfig.Rules); err != nil {
		return nil, err
	}
	return ruleConfig.Rules, nil
}

func parseTOMLRules(path string) ([]app.Rule, error) {
	ruleConfig := app.RuleConfig{}
	if _, err := toml.DecodeFile(path, &ruleConfig); err != nil {
		return nil, fmt.Errorf("parsing TOML rules file %q: %w", path, err)
	}
	for i := range ruleConfig.Rules {
		rule := &ruleConfig.Rules[i]
		if rule.StringPattern == "" {
			return nil, fmt.Errorf("TOML rules file %q contains rule %q with empty regex", path, rule.ID)
		}
		compiled, err := regexp.Compile(rule.StringPattern)
		if err != nil {
			return nil, fmt.Errorf("TOML rules file %q contains invalid regex %q: %w", path, rule.StringPattern, err)
		}
		rule.Pattern = compiled
	}
	if err := validateRules(path, ruleConfig.Rules); err != nil {
		return nil, err
	}
	return ruleConfig.Rules, nil
}

func parseTextRules(path string, file *os.File) ([]app.Rule, error) {
	var rules []app.Rule
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	idCount := 1
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") ||
			strings.HasPrefix(line, " -") || strings.Contains(line, "++++++") {
			continue
		}

		compiled, err := regexp.Compile(line)
		if err != nil {
			return nil, fmt.Errorf("text rules file %q line %d contains invalid regex: %w", path, lineNumber, err)
		}

		id := fmt.Sprintf("Rule-%d", idCount)
		rules = append(rules, app.Rule{
			ID:             id,
			Pattern:        compiled,
			StringPattern:  line,
			Description:    fmt.Sprintf("Description for %s", id),
			SmartFiltering: false,
		})
		idCount++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading text rules file %q: %w", path, err)
	}
	if err := validateRules(path, rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func validateRules(path string, rules []app.Rule) error {
	for i, rule := range rules {
		if rule.Pattern == nil {
			return fmt.Errorf("rules file %q contains rule at index %d with empty or uncompilable pattern", path, i)
		}
		if strings.TrimSpace(rule.ID) == "" {
			return fmt.Errorf("rules file %q contains rule with pattern %q that has no id", path, rule.StringPattern)
		}
	}
	return nil
}
