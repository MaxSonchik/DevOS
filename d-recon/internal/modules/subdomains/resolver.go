package subdomains

import (
	"d-recon/internal/core"
	"d-recon/internal/utils"
	"net"
	"time"
)

type DNSResolver struct {
	config *core.Config
}

type DNSResult struct {
	Subdomain string
	IPs       []string
	Status    string
}

func (d *DNSResolver) Name() string {
	return "dns_resolver"
}

func (d *DNSResolver) IsEnabled() bool {
	return true
}

func (d *DNSResolver) Run(target string, config *core.Config) (*core.ModuleResult, error) {
	utils.Logger.Infof("Starting DNS resolution for subdomains of: %s", target)

	// Читаем найденные субдомены из файла
	subdomains, err := d.readSubdomainsFromFile(target, config.OutputDir)
	if err != nil {
		return nil, err
	}

	// Резолвим первые 100 субдоменов для демонстрации
	maxResolve := 100
	if len(subdomains) < maxResolve {
		maxResolve = len(subdomains)
	}

	resolved := d.resolveSubdomains(subdomains[:maxResolve])

	result := &core.ModuleResult{
		Module:    d.Name(),
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"target":          target,
			"resolvedDomains": resolved,
			"resolvedCount":   len(resolved),
			"totalDomains":    len(subdomains),
		},
	}

	utils.Logger.Infof("Resolved %d out of %d subdomains", len(resolved), len(subdomains))
	return result, nil
}

func (d *DNSResolver) readSubdomainsFromFile(target, outputDir string) ([]string, error) {
	// В реальности нужно читать файл, но для демо вернем тестовые данные
	return []string{
		"www." + target,
		"api." + target,
		"mail." + target,
		"blog." + target,
		"shop." + target,
		"test." + target,
		"dev." + target,
		"staging." + target,
		"cdn." + target,
		"app." + target,
	}, nil
}

func (d *DNSResolver) resolveSubdomains(subdomains []string) []DNSResult {
	var results []DNSResult

	for _, subdomain := range subdomains {
		result := DNSResult{
			Subdomain: subdomain,
			Status:    "failed",
		}

		ips, err := net.LookupIP(subdomain)
		if err == nil {
			for _, ip := range ips {
				result.IPs = append(result.IPs, ip.String())
			}
			result.Status = "resolved"
		}

		results = append(results, result)

		// Небольшая задержка чтобы не спамить DNS
		time.Sleep(100 * time.Millisecond)
	}

	return results
}
