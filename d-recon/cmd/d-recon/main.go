package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"d-recon/internal/core"
	"d-recon/internal/modules/osint"
	"d-recon/internal/modules/subdomains"
	"d-recon/internal/modules/web"
	"d-recon/internal/utils"
	"d-recon/pkg/orchestrator"
	"d-recon/pkg/reporting"

	"github.com/spf13/cobra"
)

var (
	target       string
	profile      string
	outputFormat string
	outputDir    string
	verbose      bool
)

var rootCmd = &cobra.Command{
	Use:   "d-recon",
	Short: "Advanced reconnaissance orchestrator",
	Long:  `d-recon is an advanced tool for comprehensive target reconnaissance`,
	Run: func(cmd *cobra.Command, args []string) {
		utils.InitLogger(verbose)

		utils.Logger.Info("Starting d-recon...")

		config := &core.Config{
			Target:       target,
			Profile:      profile,
			OutputFormat: outputFormat,
			OutputDir:    outputDir,
			Verbose:      verbose,
		}

		utils.Logger.Infof("Target: %s", config.Target)
		utils.Logger.Infof("Profile: %s", config.Profile)
		utils.Logger.Infof("Output format: %s", config.OutputFormat)
		utils.Logger.Infof("Output directory: %s", config.OutputDir)

		// Создаем директорию для результатов
		if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
			utils.Logger.Errorf("Failed to create output directory: %v", err)
			return
		}

		runReconnaissance(config)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&target, "target", "t", "", "Target domain or IP")
	rootCmd.PersistentFlags().StringVarP(&profile, "profile", "p", "quick", "Scan profile (quick, full, stealth)")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output-format", "f", "text", "Output format (text, json, html)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output-dir", "o", "results", "Output directory")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	rootCmd.MarkPersistentFlagRequired("target")
}

func runReconnaissance(config *core.Config) {
	utils.Logger.Infof("Starting reconnaissance for target: %s", config.Target)

	// Создаем оркестратор и запускаем сканирование
	orchestrator := orchestrator.NewOrchestrator(config)
	results := orchestrator.Run(config.Target)

	// Выводим результаты
	printResults(results, config)

	// Генерируем отчеты
	reportGenerator := reporting.NewReportGenerator(results, config)
	if err := reportGenerator.GenerateReports(); err != nil {
		utils.Logger.Errorf("Failed to generate reports: %v", err)
	} else {
		utils.Logger.Info("Reports saved to: " + config.OutputDir + "/reports/")
	}
}

func printResults(results *core.ReconResults, config *core.Config) {
	utils.Logger.Info("========================================")
	utils.Logger.Infof("Reconnaissance results for: %s", results.Target)
	utils.Logger.Infof("Scan duration: %v", results.EndTime.Sub(results.StartTime))
	utils.Logger.Info("========================================")

	for moduleName, moduleResult := range results.Modules {
		utils.Logger.Infof("=== Module: %s ===", moduleName)

		if moduleResult.Error != "" {
			utils.Logger.Errorf("Error: %s", moduleResult.Error)
			continue
		}

		if data, ok := moduleResult.Data.(map[string]interface{}); ok {
			// Обработка субдоменов
			if subdomains, exists := data["subdomains"]; exists {
				if subs, ok := subdomains.([]string); ok {
					utils.Logger.Infof("Found %d subdomains", len(subs))

					// Показываем только первые 10 результатов
					maxShow := 10
					if len(subs) < maxShow {
						maxShow = len(subs)
					}

					utils.Logger.Info("First 10 subdomains:")
					for i := 0; i < maxShow; i++ {
						utils.Logger.Infof("  %d. %s", i+1, subs[i])
					}

					if len(subs) > maxShow {
						utils.Logger.Infof("  ... and %d more subdomains", len(subs)-maxShow)
					}

					// Сохраняем полный список в файл
					saveSubdomainsToFile(subs, config.OutputDir, config.Target)
				}
			}

			// Обработка сканирования портов
			if openPorts, exists := data["openPorts"]; exists {
				if ports, ok := openPorts.([]core.Port); ok {
					utils.Logger.Infof("Open ports on %s:", data["ip"])
					for _, port := range ports {
						utils.Logger.Infof("  %d/%s - %s (%s)", port.Number, port.Protocol, port.Service, port.State)
					}

					// Показываем тип сканирования
					if scanType, exists := data["scanType"]; exists {
						utils.Logger.Infof("  Scan type: %s", scanType)
					}

					// Показываем сервисы
					if services, exists := data["services"]; exists {
						if svcs, ok := services.([]string); ok && len(svcs) > 0 {
							utils.Logger.Infof("  Services: %s", strings.Join(svcs, ", "))
						}
					}
				}
			}

			// Обработка DNS резолвинга
			if resolvedDomains, exists := data["resolvedDomains"]; exists {
				if domains, ok := resolvedDomains.([]subdomains.DNSResult); ok {
					utils.Logger.Info("DNS Resolution results:")
					resolvedCount := 0
					for _, domain := range domains {
						if domain.Status == "resolved" {
							utils.Logger.Infof("  ✅ %s -> %s", domain.Subdomain, strings.Join(domain.IPs, ", "))
							resolvedCount++
						} else {
							utils.Logger.Infof("  ❌ %s - failed to resolve", domain.Subdomain)
						}
					}
					utils.Logger.Infof("  Resolved: %d/%d", resolvedCount, len(domains))
				}
			}

			// Обработка веб-сканирования
			if webResults, exists := data["webResults"]; exists {
				if results, ok := webResults.([]web.HTTPResult); ok {
					utils.Logger.Info("Web services discovered:")
					for _, service := range results {
						utils.Logger.Infof("  %s [%d] - %s", service.URL, service.StatusCode, service.Title)
						if len(service.Tech) > 0 {
							utils.Logger.Infof("    Technologies: %s", strings.Join(service.Tech, ", "))
						}
					}
				}
			}

			// Обработка сканирования уязвимостей
			if vulnData, exists := data["vulnerabilities"]; exists {
				if vulns, ok := vulnData.([]interface{}); ok {
					utils.Logger.Info("Vulnerabilities discovered:")
					for _, vuln := range vulns {
						if vulnMap, ok := vuln.(map[string]interface{}); ok {
							severity := "unknown"
							name := "unknown"
							matchedAt := "unknown"

							if info, exists := vulnMap["info"].(map[string]interface{}); exists {
								if s, exists := info["severity"].(string); exists {
									severity = s
								}
								if n, exists := info["name"].(string); exists {
									name = n
								}
							}
							if m, exists := vulnMap["matched-at"].(string); exists {
								matchedAt = m
							}

							utils.Logger.Infof("  [%s] %s - %s", strings.ToUpper(severity), name, matchedAt)
						}
					}

					// Показываем статистику
					if critical, exists := data["criticalCount"]; exists {
						utils.Logger.Infof("  Critical: %d", critical)
					}
					if high, exists := data["highCount"]; exists {
						utils.Logger.Infof("  High: %d", high)
					}
					if medium, exists := data["mediumCount"]; exists {
						utils.Logger.Infof("  Medium: %d", medium)
					}
					if low, exists := data["lowCount"]; exists {
						utils.Logger.Infof("  Low: %d", low)
					}
				}
			}

			// Обработка OSINT информации
			if whois, exists := data["whois"]; exists {
				if whoisInfo, ok := whois.(*osint.WHOISInfo); ok {
					utils.Logger.Info("WHOIS Information:")
					utils.Logger.Infof("  Registrar: %s", whoisInfo.Registrar)
					utils.Logger.Infof("  Created: %s", whoisInfo.CreatedDate)
					utils.Logger.Infof("  Expires: %s", whoisInfo.ExpiryDate)
					utils.Logger.Infof("  Status: %s", whoisInfo.Status)
					if len(whoisInfo.NameServers) > 0 {
						utils.Logger.Infof("  Name Servers: %s", strings.Join(whoisInfo.NameServers, ", "))
					}
				}
			}

			if waybackURLs, exists := data["wayback_urls"]; exists {
				if urls, ok := waybackURLs.([]osint.WaybackURL); ok {
					utils.Logger.Info("Wayback Machine URLs:")
					for i, url := range urls {
						if i >= 5 { // Показываем только первые 5
							utils.Logger.Infof("  ... and %d more URLs", len(urls)-5)
							break
						}
						utils.Logger.Infof("  %s [%d] - %s", url.Date, url.Status, url.URL)
					}
				}
			}

			if leaks, exists := data["leaks"]; exists {
				if leakInfo, ok := leaks.([]osint.LeakInfo); ok {
					utils.Logger.Info("Data Leak Check:")
					for _, leak := range leakInfo {
						status := "✅"
						if leak.Found {
							status = "⚠️"
						}
						utils.Logger.Infof("  %s %s: %s (%s)", status, leak.Source, leak.Details, leak.Severity)
					}
				}
			}

			// Показываем OSINT summary
			if summary, exists := data["summary"]; exists {
				if sm, ok := summary.(map[string]interface{}); ok {
					if waybackCount, exists := sm["wayback_count"]; exists {
						utils.Logger.Infof("  Wayback URLs: %d", waybackCount)
					}
					if leaksFound, exists := sm["leaks_found"]; exists {
						utils.Logger.Infof("  Potential Leaks: %d", leaksFound)
					}
				}
			}

			// Показываем счетчик
			if count, exists := data["count"]; exists {
				utils.Logger.Infof("Total count: %d", count)
			}
		}
	}
}

func saveSubdomainsToFile(subdomains []string, outputDir, target string) {
	filename := filepath.Join(outputDir, target+"_subdomains.txt")

	file, err := os.Create(filename)
	if err != nil {
		utils.Logger.Errorf("Failed to create subdomains file: %v", err)
		return
	}
	defer file.Close()

	for _, subdomain := range subdomains {
		file.WriteString(subdomain + "\n")
	}

	utils.Logger.Infof("Full subdomains list saved to: %s", filename)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
