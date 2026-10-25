package hunt

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/darkLabz001/php2shell-audit/internal/model"
)

var defaultSessionPaths = []string{
	"/var/lib/php/sessions",
	"/var/lib/php5",
	"/var/lib/php/session",
}

// ScanSessions looks for PHP session files that contain serialized objects,
// injected PHP, or upload-progress bookkeeping from outside the application.
func ScanSessions(paths []string, since time.Time, all bool) ([]model.Finding, []string) {
	if len(paths) == 0 {
		paths = defaultSessionPaths
	}
	var findings []model.Finding
	var warnings []string
	seenDirs := map[string]bool{}

	for _, dir := range paths {
		if seenDirs[dir] {
			continue
		}
		seenDirs[dir] = true
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			base := filepath.Base(path)
			if !strings.HasPrefix(base, "sess_") {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if !all && !since.IsZero() && info.ModTime().Before(since) {
				return nil
			}
			if info.Size() > 4*1024*1024 {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			text := string(data)

			hasPHP := strings.Contains(text, "<?php") || strings.Contains(text, "<?=")
			hasProgress := strings.Contains(text, "upload_progress_")
			oversized := info.Size() > 1024*1024

			// Upload-progress bookkeeping on its own is expected whenever an
			// application uses that feature, so it is only reported when it is
			// co-located with executable PHP or an implausibly large session.
			if !hasPHP && !oversized {
				return nil
			}

			var reasons []string
			sev := model.Medium
			title := "Anomalous PHP session file"
			if hasPHP {
				reasons = append(reasons, "contains a PHP open tag")
				sev = model.Critical
				title = "PHP code in a session file (likely webshell)"
			}
			if hasProgress {
				reasons = append(reasons, "contains upload_progress_ bookkeeping")
			}
			if oversized {
				reasons = append(reasons, fmt.Sprintf("oversized session file (%s)", humanBytes(info.Size())))
				if sev < model.Medium {
					sev = model.Medium
				}
			}
			findings = append(findings, model.Finding{
				ID: "P2S-HUNT-014", Title: title, Severity: sev,
				Category: "compromise", Surface: "host", Target: path, Confidence: "medium",
				Detail: "Session files are not executable and should only contain serialized session values. " +
					strings.Join(reasons, "; ") + ". A session file that contains PHP code is a webshell written through a session path; " +
					"the session upload-progress handler runs before application code and is one of the php2shell trigger paths.",
				Evidence: []string{
					"path: " + path,
					"size: " + humanBytes(info.Size()),
					"modified: " + info.ModTime().UTC().Format(time.RFC3339),
					"reasons: " + strings.Join(reasons, ", "),
				},
				Remediation: "Preserve the file as evidence, then remove it. Review requests carrying the matching PHPSESSID and rotate secrets the PHP worker could read.",
				Refs:        []string{model.GHSA109619},
				CVEs:        []string{model.CVE109619},
			})
			return nil
		})
	}
	return findings, warnings
}
