package ml

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"d-env/modules"
)

type Module struct {
	ShowDataSize bool
}

func (m *Module) Gather() (modules.ModuleResult, error) {
	result := modules.ModuleResult{
		Data: make(map[string]interface{}),
	}

	dataDirs := []string{}
	notebookCount := 0
	configFiles := []string{}

	// Find data directories
	potentialDataDirs := []string{"data", "dataset", "datasets", "models"}
	for _, dir := range potentialDataDirs {
		if _, err := os.Stat(dir); err == nil {
			dataDirs = append(dataDirs, dir)
		}
	}

	// Count notebooks
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if strings.HasSuffix(path, ".ipynb") {
			notebookCount++
		}

		if strings.Contains(path, "config") && (strings.HasSuffix(path, ".yml") ||
			strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".json")) {
			configFiles = append(configFiles, path)
		}

		return nil
	})

	// Calculate data directory sizes if requested
	dataSizes := make(map[string]int64)
	if m.ShowDataSize {
		for _, dir := range dataDirs {
			size := m.calculateDirSize(dir)
			dataSizes[dir] = size
		}
	}

	// Build display
	var display strings.Builder
	display.WriteString("🤖 ML: ")

	if len(dataDirs) > 0 {
		display.WriteString(fmt.Sprintf("Data directories: %s", strings.Join(dataDirs, ", ")))
		if m.ShowDataSize {
			for _, dir := range dataDirs {
				if size, exists := dataSizes[dir]; exists {
					display.WriteString(fmt.Sprintf(" [%s]", formatSize(size)))
				}
			}
		}
	}

	if notebookCount > 0 {
		if len(dataDirs) > 0 {
			display.WriteString(" | ")
		}
		display.WriteString(fmt.Sprintf("Notebooks: %d .ipynb files", notebookCount))
	}

	if len(configFiles) > 0 {
		if len(dataDirs) > 0 || notebookCount > 0 {
			display.WriteString(" | ")
		}
		display.WriteString(fmt.Sprintf("Configs: %d files", len(configFiles)))
	}

	if len(dataDirs) == 0 && notebookCount == 0 && len(configFiles) == 0 {
		display.WriteString("No ML-specific artifacts found")
	}

	result.Data["data_directories"] = dataDirs
	result.Data["notebook_count"] = notebookCount
	result.Data["config_files"] = configFiles
	result.Data["data_sizes"] = dataSizes
	result.Display = display.String()

	return result, nil
}

func (m *Module) calculateDirSize(path string) int64 {
	var size int64
	filepath.Walk(path, func(subPath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size
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
