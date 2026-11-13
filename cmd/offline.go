package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/tillson/git-hound/internal/app"
)

var (
	offlineRulesPath  string
	offlineFileExts   string
	offlineThreads    int
	offlineNoScoring  bool
	offlineNoFiles    bool
	offlineNoKeywords bool
	offlineJSON       bool
	offlineDebug      bool
)

var offlineCmd = &cobra.Command{
	Use:   "offline <directory>",
	Short: "Scan a checked-out directory for secrets without contacting GitHub",
	Long: `Offline mode scans a local, already checked-out directory using GitHound's
YAML/TOML/text rule sets, base64 decoding, smart filtering, scoring and
interesting-extension checks entirely on the local machine. No network requests
are made. Findings are emitted deterministically, ordered by relative path,
line number, column and rule ID.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		if strings.TrimSpace(target) == "" {
			return fmt.Errorf("scan directory must not be empty")
		}
		targetInfo, err := os.Stat(target)
		if err != nil {
			return fmt.Errorf("invalid scan directory: %w", err)
		}
		if !targetInfo.IsDir() {
			return fmt.Errorf("scan path %q is not a directory", target)
		}
		if offlineThreads <= 0 {
			return fmt.Errorf("--threads must be a positive integer, got %d", offlineThreads)
		}
		if strings.TrimSpace(offlineRulesPath) == "" {
			return fmt.Errorf("--rules must not be empty")
		}
		if _, err := os.Stat(offlineRulesPath); err != nil {
			return fmt.Errorf("invalid rules path: %w", err)
		}
		if offlineFileExts != "" {
			if _, err := os.Stat(offlineFileExts); err != nil {
				return fmt.Errorf("invalid --file-exts path: %w", err)
			}
		}

		rules, err := LoadRulesOffline(offlineRulesPath)
		if err != nil {
			return err
		}

		flags := app.GetFlags()
		flags.TextRegexes = rules
		flags.Threads = offlineThreads
		flags.NoScoring = offlineNoScoring
		flags.NoFiles = offlineNoFiles
		flags.NoKeywords = offlineNoKeywords
		flags.FileExtensions = offlineFileExts
		flags.Debug = offlineDebug

		findings, err := app.ScanOfflineDirectory(target)
		if err != nil {
			return err
		}

		if err := printOfflineFindings(findings); err != nil {
			return err
		}

		if offlineDebug {
			fmt.Fprintf(os.Stderr, "[*] Offline scan complete: %d finding(s), %d rule(s) loaded.\n", len(findings), len(rules))
		}
		return nil
	},
	SilenceUsage: true,
}

func init() {
	offlineCmd.Flags().StringVar(&offlineRulesPath, "rules", "rules/", "Path to a rule file (.yml/.yaml/.toml/.txt) or a directory of rule files.")
	offlineCmd.Flags().StringVar(&offlineFileExts, "file-exts", "", "Path to a file containing interesting file extensions, one per line.")
	offlineCmd.Flags().IntVar(&offlineThreads, "threads", 10, "Number of files to scan concurrently (must be positive).")
	offlineCmd.Flags().BoolVar(&offlineNoScoring, "no-scoring", false, "Disable score-based false-positive filtering.")
	offlineCmd.Flags().BoolVar(&offlineNoFiles, "no-files", false, "Disable interesting file-extension hits.")
	offlineCmd.Flags().BoolVar(&offlineNoKeywords, "no-keywords", false, "Disable content rule matching (extension hits only).")
	offlineCmd.Flags().BoolVar(&offlineJSON, "json", false, "Emit one JSON object per finding (JSON Lines).")
	offlineCmd.Flags().BoolVar(&offlineDebug, "debug", false, "Emit verbose progress information to stderr.")

	rootCmd.AddCommand(offlineCmd)
}

func printOfflineFindings(findings []app.OfflineFinding) error {
	for _, finding := range findings {
		if offlineJSON {
			encoded, err := json.Marshal(finding)
			if err != nil {
				return fmt.Errorf("encoding finding as JSON: %w", err)
			}
			fmt.Println(string(encoded))
			continue
		}
		fmt.Printf("%s:%d:%d: [%s] %s\n",
			filepath.ToSlash(finding.File),
			finding.Line,
			finding.Column,
			finding.RuleID,
			sanitizeLine(finding.LineText),
		)
	}
	return nil
}

func sanitizeLine(line string) string {
	line = strings.ReplaceAll(line, "\n", " ")
	line = strings.ReplaceAll(line, "\r", " ")
	line = strings.ReplaceAll(line, "\t", " ")
	return strings.TrimSpace(line)
}
