package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"d-env/modules"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object" // ДОБАВЬТЕ ЭТОТ ИМПОРТ
)

type Module struct {
	FullTree bool
}

func (m *Module) Gather() (modules.ModuleResult, error) {
	result := modules.ModuleResult{
		Data: make(map[string]interface{}),
	}

	// Get project size and file count
	totalSize := int64(0)
	fileCount := 0

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if shouldIgnore(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if !info.IsDir() {
			fileCount++
			totalSize += info.Size()
		}

		return nil
	})

	if err != nil {
		return result, err
	}

	result.Data["file_count"] = fileCount
	result.Data["total_size"] = totalSize

	// Get git history for project age
	repo, err := git.PlainOpen(".")
	var firstCommit, lastCommit time.Time

	if err == nil {
		commitIter, err := repo.Log(&git.LogOptions{Order: git.LogOrderCommitterTime})
		if err == nil {
			// Last commit
			if last, err := commitIter.Next(); err == nil {
				lastCommit = last.Author.When
				result.Data["last_commit"] = lastCommit.Format(time.RFC3339)
			}

			// First commit (iterate to the end)
			var first *object.Commit
			for {
				commit, err := commitIter.Next()
				if err != nil {
					break
				}
				first = commit
			}
			if first != nil {
				firstCommit = first.Author.When
				result.Data["first_commit"] = firstCommit.Format(time.RFC3339)
			}
		}
	}

	// Generate tree structure
	tree := m.generateTree(".")
	result.Data["tree"] = tree

	// Build display
	var display strings.Builder
	display.WriteString("📁 PROJECT: ")
	display.WriteString(fmt.Sprintf("%d files, %s", fileCount, formatSize(totalSize)))

	if !firstCommit.IsZero() {
		age := time.Since(firstCommit)
		display.WriteString(fmt.Sprintf(", Age: %.0f days", age.Hours()/24))
	}

	display.WriteString("\n")
	display.WriteString(tree)

	result.Display = display.String()
	return result, nil
}

func (m *Module) generateTree(root string) string {
	var builder strings.Builder
	m.buildTreeLevel(root, "", &builder, 0)
	return builder.String()
}

func (m *Module) buildTreeLevel(path, prefix string, builder *strings.Builder, depth int) {
	if depth > 3 { // Limit depth for readability
		return
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return
	}

	// Filter and sort entries
	var validEntries []os.DirEntry
	for _, entry := range entries {
		if m.FullTree || !shouldIgnore(filepath.Join(path, entry.Name())) {
			validEntries = append(validEntries, entry)
		}
	}

	for i, entry := range validEntries {
		isLast := i == len(validEntries)-1

		// Current level prefix
		if depth > 0 {
			if isLast {
				builder.WriteString(prefix + "└── ")
			} else {
				builder.WriteString(prefix + "├── ")
			}
		}

		builder.WriteString(entry.Name())

		if entry.IsDir() {
			builder.WriteString("/")
		}
		builder.WriteString("\n")

		if entry.IsDir() {
			newPrefix := prefix
			if depth > 0 {
				if isLast {
					newPrefix += "    "
				} else {
					newPrefix += "│   "
				}
			}
			m.buildTreeLevel(filepath.Join(path, entry.Name()), newPrefix, builder, depth+1)
		}
	}
}

func shouldIgnore(path string) bool {
	ignorePatterns := []string{
		".git", "node_modules", "__pycache__", ".venv", "venv",
		".idea", ".vscode", "dist", "build", "target",
	}

	for _, pattern := range ignorePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
