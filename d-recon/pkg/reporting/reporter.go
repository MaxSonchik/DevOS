package reporting

import (
	"d-recon/internal/core"
	"d-recon/internal/utils"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type ReportGenerator struct {
	results *core.ReconResults
	config  *core.Config
}

func NewReportGenerator(results *core.ReconResults, config *core.Config) *ReportGenerator {
	return &ReportGenerator{
		results: results,
		config:  config,
	}
}

func (r *ReportGenerator) GenerateReports() error {
	utils.Logger.Info("Generating reports...")

	// Создаем директорию для отчетов
	reportDir := filepath.Join(r.config.OutputDir, "reports")
	if err := os.MkdirAll(reportDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %v", err)
	}

	// Генерируем отчеты в разных форматах
	formats := []string{"json", "html", "md"}
	for _, format := range formats {
		filename := filepath.Join(reportDir, fmt.Sprintf("%s_report.%s", r.results.Target, format))

		switch format {
		case "json":
			if err := r.generateJSONReport(filename); err != nil {
				utils.Logger.Errorf("Failed to generate JSON report: %v", err)
			}
		case "html":
			if err := r.generateHTMLReport(filename); err != nil {
				utils.Logger.Errorf("Failed to generate HTML report: %v", err)
			}
		case "md":
			if err := r.generateMarkdownReport(filename); err != nil {
				utils.Logger.Errorf("Failed to generate Markdown report: %v", err)
			}
		}
	}

	utils.Logger.Info("Reports generated successfully")
	return nil
}

func (r *ReportGenerator) generateJSONReport(filename string) error {
	jsonData, err := r.toJSON()
	if err != nil {
		return err
	}

	return os.WriteFile(filename, jsonData, 0644)
}

func (r *ReportGenerator) generateHTMLReport(filename string) error {
	htmlContent := r.toHTML()
	return os.WriteFile(filename, []byte(htmlContent), 0644)
}

func (r *ReportGenerator) generateMarkdownReport(filename string) error {
	mdContent := r.toMarkdown()
	return os.WriteFile(filename, []byte(mdContent), 0644)
}

func (r *ReportGenerator) toJSON() ([]byte, error) {
	report := map[string]interface{}{
		"target":    r.results.Target,
		"timestamp": time.Now().Format(time.RFC3339),
		"duration":  r.results.EndTime.Sub(r.results.StartTime).String(),
		"modules":   r.results.Modules,
		"summary":   r.generateSummary(),
	}

	return json.MarshalIndent(report, "", "  ")
}

func (r *ReportGenerator) toHTML() string {
	summary := r.generateSummary()

	html := `<!DOCTYPE html>
<html>
<head>
    <title>Reconnaissance Report - ` + r.results.Target + `</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .module { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .success { color: green; }
        .warning { color: orange; }
        .error { color: red; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Reconnaissance Report</h1>
        <p><strong>Target:</strong> ` + r.results.Target + `</p>
        <p><strong>Scan Duration:</strong> ` + r.results.EndTime.Sub(r.results.StartTime).String() + `</p>
        <p><strong>Timestamp:</strong> ` + time.Now().Format("2006-01-02 15:04:05") + `</p>
    </div>
    
    <div class="module">
        <h2>Executive Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>`

	for _, item := range summary {
		html += `<tr><td>` + item.Metric + `</td><td>` + item.Value + `</td></tr>`
	}

	html += `</table></div>`

	for moduleName, moduleResult := range r.results.Modules {
		html += `<div class="module">
            <h2>` + moduleName + `</h2>
            <p><strong>Status:</strong> <span class="success">Completed</span></p>
            <p><strong>Timestamp:</strong> ` + moduleResult.Timestamp.Format("2006-01-02 15:04:05") + `</p>`

		if moduleResult.Error != "" {
			html += `<p><strong>Error:</strong> <span class="error">` + moduleResult.Error + `</span></p>`
		}

		html += `</div>`
	}

	html += `</body></html>`
	return html
}

func (r *ReportGenerator) toMarkdown() string {
	summary := r.generateSummary()

	md := "# Reconnaissance Report\n\n"
	md += "**Target:** " + r.results.Target + "\n\n"
	md += "**Scan Duration:** " + r.results.EndTime.Sub(r.results.StartTime).String() + "\n\n"
	md += "**Timestamp:** " + time.Now().Format("2006-01-02 15:04:05") + "\n\n"

	md += "## Executive Summary\n\n"
	for _, item := range summary {
		md += "- **" + item.Metric + ":** " + item.Value + "\n"
	}
	md += "\n"

	md += "## Module Results\n\n"
	for moduleName, moduleResult := range r.results.Modules {
		md += "### " + moduleName + "\n\n"
		md += "- **Status:** Completed\n"
		md += "- **Timestamp:** " + moduleResult.Timestamp.Format("2006-01-02 15:04:05") + "\n"
		if moduleResult.Error != "" {
			md += "- **Error:** " + moduleResult.Error + "\n"
		}
		md += "\n"
	}

	return md
}

type SummaryItem struct {
	Metric string
	Value  string
}

func (r *ReportGenerator) generateSummary() []SummaryItem {
	var summary []SummaryItem

	// Считаем общую статистику
	subdomainCount := 0
	openPorts := 0
	webServices := 0
	vulnerabilities := 0

	for moduleName, moduleResult := range r.results.Modules {
		if data, ok := moduleResult.Data.(map[string]interface{}); ok {
			switch moduleName {
			case "subdomains":
				if count, exists := data["count"]; exists {
					subdomainCount = count.(int)
				}
			case "ports":
				if count, exists := data["count"]; exists {
					openPorts = count.(int)
				}
			case "web":
				if count, exists := data["count"]; exists {
					webServices = count.(int)
				}
			case "vulnerabilities":
				if count, exists := data["count"]; exists {
					vulnerabilities = count.(int)
				}
			}
		}
	}

	summary = append(summary, SummaryItem{"Subdomains Found", fmt.Sprintf("%d", subdomainCount)})
	summary = append(summary, SummaryItem{"Open Ports", fmt.Sprintf("%d", openPorts)})
	summary = append(summary, SummaryItem{"Web Services", fmt.Sprintf("%d", webServices)})
	summary = append(summary, SummaryItem{"Vulnerabilities", fmt.Sprintf("%d", vulnerabilities)})
	summary = append(summary, SummaryItem{"Modules Executed", fmt.Sprintf("%d", len(r.results.Modules))})

	return summary
}
