package docker

import (
	"fmt"
	"os"
	"strings"

	"d-env/modules"
)

type Module struct{}

func (m *Module) Gather() (modules.ModuleResult, error) {
	result := modules.ModuleResult{
		Data: make(map[string]interface{}),
	}

	// Check for Docker files
	dockerFiles := []string{
		"Dockerfile",
		"docker-compose.yml",
		"docker-compose.yaml",
		"compose.yml",
	}

	foundFiles := []string{}
	for _, file := range dockerFiles {
		if _, err := os.Stat(file); err == nil {
			foundFiles = append(foundFiles, file)
		}
	}

	if len(foundFiles) == 0 {
		result.Data["docker_files"] = []string{}
		result.Display = "🐳 DOCKER: No Docker files found"
		return result, nil
	}

	result.Data["docker_files"] = foundFiles
	result.Display = fmt.Sprintf("🐳 DOCKER: %s found", strings.Join(foundFiles, ", "))

	return result, nil
}
