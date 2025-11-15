package dependencies

import (
	"encoding/json"
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

	var foundDeps []string
	var displayLines []string

	// Check for various dependency files
	dependencyFiles := map[string]func(string){
		"package.json":     m.parsePackageJSON,
		"pyproject.toml":   m.parsePyProjectTOML,
		"requirements.txt": m.parseRequirementsTXT,
		"go.mod":           m.parseGoMod,
		"Cargo.toml":       m.parseCargoTOML,
		"pom.xml":          m.parsePomXML,
	}

	configFiles := []string{".env", ".env.example", "config.yaml", "application.properties"}

	for file, parser := range dependencyFiles {
		if _, err := os.Stat(file); err == nil {
			foundDeps = append(foundDeps, file)
			parser(file)
		}
	}

	for _, file := range configFiles {
		if _, err := os.Stat(file); err == nil {
			foundDeps = append(foundDeps, file)
		}
	}

	// Check for virtual environment
	venvInfo := m.checkVirtualEnv()

	// Build display
	var display strings.Builder
	display.WriteString("📦 DEPENDENCIES: ")

	if len(foundDeps) > 0 {
		display.WriteString(fmt.Sprintf("%s found", strings.Join(foundDeps, ", ")))
	} else {
		display.WriteString("No dependency files found")
	}

	if len(displayLines) > 0 {
		display.WriteString("\n")
		display.WriteString(strings.Join(displayLines, "\n"))
	}

	if venvInfo != "" {
		display.WriteString("\n")
		display.WriteString(venvInfo)
	}

	result.Data["dependency_files"] = foundDeps
	result.Data["virtual_env"] = venvInfo != ""
	result.Display = display.String()

	return result, nil
}

func (m *Module) parsePackageJSON(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err == nil {
		// Could parse dependencies here
	}
}

func (m *Module) parsePyProjectTOML(file string) {
	// Simplified TOML parsing
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	// Basic parsing for demonstration
	content := string(data)
	if strings.Contains(content, "[tool.poetry]") || strings.Contains(content, "[project]") {
		// Extract basic info
	}
}

func (m *Module) parseRequirementsTXT(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	deps := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			deps++
		}
	}
}

func (m *Module) parseGoMod(file string) {
	// Basic go.mod parsing
}

func (m *Module) parseCargoTOML(file string) {
	// Basic Cargo.toml parsing
}

func (m *Module) parsePomXML(file string) {
	// Basic pom.xml parsing
}

func (m *Module) checkVirtualEnv() string {
	venvDirs := []string{".venv", "venv", "env"}
	for _, dir := range venvDirs {
		if _, err := os.Stat(dir); err == nil {
			return fmt.Sprintf("🐍 Virtual Environment: Found (%s)", dir)
		}
	}

	// Check environment variables
	if os.Getenv("VIRTUAL_ENV") != "" {
		return fmt.Sprintf("🐍 Virtual Environment: Activated (%s)", os.Getenv("VIRTUAL_ENV"))
	}

	return ""
}
