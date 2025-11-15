package security

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"d-env/modules"
)

type Module struct{}

func (m *Module) Gather() (modules.ModuleResult, error) {
	result := modules.ModuleResult{
		Data: make(map[string]interface{}),
	}

	secretsFound := []string{}
	permissionWarnings := []string{}

	// Scan for secrets in recent files
	m.scanForSecrets(&secretsFound)

	// Check file permissions
	m.checkFilePermissions(&permissionWarnings)

	// Build display
	var display strings.Builder
	display.WriteString("🔒 SECURITY: ")

	if len(secretsFound) == 0 {
		display.WriteString("🟢 No obvious secrets found")
	} else {
		display.WriteString(fmt.Sprintf("🔴 %d potential secrets found", len(secretsFound)))
	}

	if len(permissionWarnings) > 0 {
		if len(secretsFound) > 0 {
			display.WriteString(" | ")
		}
		display.WriteString(fmt.Sprintf("🟡 %d permission warnings", len(permissionWarnings)))
	}

	if len(permissionWarnings) > 0 {
		display.WriteString("\n")
		for _, warning := range permissionWarnings {
			display.WriteString("             " + warning + "\n")
		}
	}

	result.Data["secrets_found"] = secretsFound
	result.Data["permission_warnings"] = permissionWarnings
	result.Display = strings.TrimSpace(display.String())

	return result, nil
}

func (m *Module) scanForSecrets(secretsFound *[]string) {
	secretPatterns := map[string]*regexp.Regexp{
		"AWS Key":          regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"AWS Secret":       regexp.MustCompile(`[[:alnum:]]{40}`),
		"Private Key":      regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`),
		"API Key":          regexp.MustCompile(`[a-zA-Z0-9]{32,}`),
		"Email + Password": regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}.*[a-zA-Z0-9]{8,}`),
	}

	// Scan files in current directory
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Skip large files and binaries
		if info.Size() > 1024*1024 { // 1MB
			return nil
		}

		if shouldIgnore(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		text := string(content)
		for secretType, pattern := range secretPatterns {
			if pattern.MatchString(text) {
				*secretsFound = append(*secretsFound, fmt.Sprintf("%s in %s", secretType, path))
			}
		}

		return nil
	})
}

func (m *Module) checkFilePermissions(warnings *[]string) {
	sensitiveFiles := []string{".env", "id_rsa", "id_dsa", "*.key", "*.pem"}

	for _, pattern := range sensitiveFiles {
		matches, _ := filepath.Glob(pattern)
		for _, file := range matches {
			info, err := os.Stat(file)
			if err != nil {
				continue
			}

			perm := info.Mode().Perm()
			if perm&0002 != 0 { // World writable
				*warnings = append(*warnings, fmt.Sprintf("File '%s' is world-writable (%04o)", file, perm))
			} else if perm&0004 != 0 && isSensitiveFile(file) { // World readable for sensitive files
				*warnings = append(*warnings, fmt.Sprintf("File '%s' is world-readable (%04o)", file, perm))
			}
		}
	}
}

func isSensitiveFile(path string) bool {
	sensitivePatterns := []string{".env", ".key", ".pem", "id_rsa", "id_dsa", "config"}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func shouldIgnore(path string) bool {
	ignorePatterns := []string{
		".git", "node_modules", "__pycache__", ".venv",
	}
	for _, pattern := range ignorePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}
