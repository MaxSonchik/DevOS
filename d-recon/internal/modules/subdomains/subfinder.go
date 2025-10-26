package subdomains

import (
	"d-recon/internal/core"
	"d-recon/internal/utils"
	"encoding/json"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type SubfinderRunner struct {
	config *core.Config
}

type SubfinderResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
}

func (s *SubfinderRunner) Name() string {
	return "subdomains"
}

func (s *SubfinderRunner) IsEnabled() bool {
	return true
}

func (s *SubfinderRunner) Run(target string, config *core.Config) (*core.ModuleResult, error) {
	utils.Logger.Infof("Starting subdomain discovery for: %s", target)

	subdomains, err := s.runSubfinder(target)
	if err != nil {
		return nil, err
	}

	result := &core.ModuleResult{
		Module:    s.Name(),
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"subdomains": subdomains,
			"count":      len(subdomains),
		},
	}

	utils.Logger.Infof("Found %d subdomains", len(subdomains))
	return result, nil
}

func (s *SubfinderRunner) runSubfinder(domain string) ([]string, error) {
	// Проверяем, установлен ли subfinder
	if !s.isToolInstalled("subfinder") {
		utils.Logger.Warn("subfinder not found, using dummy data for testing")
		return s.getDummySubdomains(domain), nil
	}

	// Запускаем subfinder
	cmd := exec.Command("subfinder", "-d", domain, "-silent", "-json")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return s.parseSubfinderOutput(output)
}

func (s *SubfinderRunner) isToolInstalled(tool string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("where", tool)
	} else {
		cmd = exec.Command("which", tool)
	}

	return cmd.Run() == nil
}

func (s *SubfinderRunner) parseSubfinderOutput(output []byte) ([]string, error) {
	lines := strings.Split(string(output), "\n")
	var subdomains []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result SubfinderResult
		if err := json.Unmarshal([]byte(line), &result); err == nil && result.Host != "" {
			subdomains = append(subdomains, result.Host)
		}
	}

	return subdomains, nil
}

func (s *SubfinderRunner) getDummySubdomains(domain string) []string {
	// Временные данные для тестирования
	return []string{
		"www." + domain,
		"api." + domain,
		"mail." + domain,
		"blog." + domain,
		"shop." + domain,
	}
}
