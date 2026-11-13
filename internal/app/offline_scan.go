package app

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	offlineMaxFileSize  = 5 * 1024 * 1024
	interestingFileRule = "interesting_filename"
)

// OfflineFinding is a single, location-stable finding produced by a local
// directory scan. It never references GitHub repositories or URLs.
type OfflineFinding struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	Column     int      `json:"column"`
	RuleID     string   `json:"rule_id"`
	RuleName   string   `json:"rule_name,omitempty"`
	Match      string   `json:"match"`
	LineText   string   `json:"line_text"`
	Attributes []string `json:"attributes,omitempty"`
	Base64     bool     `json:"base64,omitempty"`
}

type offlineFileResult struct {
	findings []OfflineFinding
	err      error
}

// ScanOfflineDirectory walks a checked-out directory and scans every eligible
// file using the same rules, decoders, extension checks and filtering semantics
// as the online dig-files pipeline, without any network access.
func ScanOfflineDirectory(root string) ([]OfflineFinding, error) {
	// Pre-warm the lazy programming-words regex so parallel scans do not race.
	_ = containsCommonWord("init")

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolving scan path %q: %w", root, err)
	}
	info, err := os.Stat(absRoot)
	if err != nil {
		return nil, fmt.Errorf("scan path %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan path %q is not a directory", root)
	}

	var files []string
	err = filepath.Walk(absRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if os.IsNotExist(walkErr) {
				return nil
			}
			return walkErr
		}
		if info.IsDir() {
			if path != absRoot && skipFolders[filepath.Base(path)] {
				return filepath.SkipDir
			}
			return nil
		}
		if skipExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking directory %q: %w", root, err)
	}

	workers := GetFlags().Threads
	if workers < 1 {
		workers = 1
	}
	semaphore := make(chan struct{}, workers)
	results := make(chan offlineFileResult, len(files))
	var wg sync.WaitGroup

	for _, file := range files {
		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			findings, err := scanOfflineFile(absRoot, file)
			results <- offlineFileResult{findings: findings, err: err}
		}(file)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []OfflineFinding
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		allFindings = append(allFindings, result.findings...)
	}
	if firstErr != nil {
		return nil, firstErr
	}

	sort.Slice(allFindings, func(i, j int) bool {
		a, b := allFindings[i], allFindings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Match < b.Match
	})

	return allFindings, nil
}

func scanOfflineFile(root, file string) ([]OfflineFinding, error) {
	relPath, err := filepath.Rel(root, file)
	if err != nil {
		return nil, fmt.Errorf("computing relative path for %q: %w", file, err)
	}
	relPath = filepath.ToSlash(relPath)

	fileInfo, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("stating %q: %w", relPath, err)
	}

	var findings []OfflineFinding
	score := 0

	extensionMatches := MatchFileExtensions(relPath, RepoSearchResult{File: relPath})
	for _, match := range extensionMatches {
		findings = append(findings, OfflineFinding{
			File:       relPath,
			Line:       1,
			Column:     1,
			RuleID:     interestingFileRule,
			Match:      match.Text,
			LineText:   getFirstNLines(file, 3),
			Attributes: []string{interestingFileRule},
		})
		score += 5
	}
	PutMatches(extensionMatches)

	// Mirror processFile semantics: extension hits are reported, and content is
	// only scanned when no extension hit was found.
	if score != 0 || fileInfo.Size() > offlineMaxFileSize {
		return findings, nil
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", relPath, err)
	}
	if isBinaryFile(data) {
		return findings, nil
	}

	content, binaryRatio := extractTextContent(data)
	if binaryRatio < 0.9 {
		return findings, nil
	}

	result := RepoSearchResult{File: relPath}
	_, score = GetMatchesForString(content, result, true)
	contentScoringEnabled := !GetFlags().NoScoring
	if contentScoringEnabled && score <= 1 {
		return nil, nil
	}
	if GetFlags().NoKeywords {
		return findings, nil
	}

	return scanOfflineLines(relPath, strings.Split(content, "\n")), nil
}

// scanOfflineLines applies the loaded rules line by line so every finding
// carries a stable line number and column.
func scanOfflineLines(relPath string, lines []string) []OfflineFinding {
	var findings []OfflineFinding
	seen := make(map[string]bool)
	// Match base64 payloads including any trailing "=" padding. The trailing
	// padding cannot live inside the \b boundary, so it is captured explicitly.
	base64TokenRegex := regexp.MustCompile(`\b[a-zA-Z0-9/+]{8,}={0,2}`)

	addFinding := func(lineNo, column int, rule Rule, matchText, lineText string, decoded bool) {
		key := fmt.Sprintf("%d|%d|%s|%s", lineNo, column, rule.ID, matchText)
		if seen[key] {
			return
		}
		seen[key] = true

		attributes := []string{rule.ID, rule.Description}
		if decoded {
			attributes = append(attributes, "base64")
		}
		findings = append(findings, OfflineFinding{
			File:       relPath,
			Line:       lineNo,
			Column:     column,
			RuleID:     rule.ID,
			RuleName:   rule.Description,
			Match:      matchText,
			LineText:   lineText,
			Attributes: attributes,
			Base64:     decoded,
		})
	}

	for lineNo, rawLine := range lines {
		line := strings.TrimSuffix(rawLine, "\r")
		if line == "" {
			continue
		}

		for _, rule := range GetFlags().TextRegexes {
			if rule.Pattern == nil {
				continue
			}
			for _, indices := range rule.Pattern.FindAllStringIndex(line, -1) {
				matchText := line[indices[0]:indices[1]]
				if !offlineRuleMatches(rule, matchText) {
					continue
				}
				addFinding(lineNo+1, indices[0]+1, rule, matchText, line, false)
			}
		}

		for _, indices := range base64TokenRegex.FindAllStringIndex(line, -1) {
			token := line[indices[0]:indices[1]]
			decodedBytes, err := base64.StdEncoding.DecodeString(token)
			if err != nil || !isPrintable(decodedBytes) {
				continue
			}
			decodedLine := string(decodedBytes)
			for _, rule := range GetFlags().TextRegexes {
				if rule.Pattern == nil {
					continue
				}
				for _, decodedIndices := range rule.Pattern.FindAllStringIndex(decodedLine, -1) {
					matchText := decodedLine[decodedIndices[0]:decodedIndices[1]]
					if !offlineRuleMatches(rule, matchText) {
						continue
					}
					addFinding(lineNo+1, indices[0]+1, rule, matchText, line, true)
				}
			}
		}
	}

	return findings
}

// offlineRuleMatches mirrors the SmartFiltering check in MatchKeywords.
func offlineRuleMatches(rule Rule, matchText string) bool {
	if !rule.SmartFiltering {
		return true
	}
	if Entropy(matchText) <= 3.5 {
		return false
	}
	return !(containsSequence(matchText) || containsCommonWord(matchText))
}
