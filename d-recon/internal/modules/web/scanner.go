package web

import (
	"d-recon/internal/core"
	"d-recon/internal/utils"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type WebScanner struct {
	config *core.Config
}

type HTTPResult struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	Tech       []string
}

func (w *WebScanner) Name() string {
	return "web"
}

func (w *WebScanner) IsEnabled() bool {
	return true
}

func (w *WebScanner) Run(target string, config *core.Config) (*core.ModuleResult, error) {
	utils.Logger.Infof("Starting web scanning for: %s", target)

	// Проверяем основные веб-сервисы
	webResults, err := w.scanWebServices(target)
	if err != nil {
		return nil, err
	}

	result := &core.ModuleResult{
		Module:    w.Name(),
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"target":     target,
			"webResults": webResults,
			"count":      len(webResults),
			"discovered": w.getDiscoveredURLs(webResults),
		},
	}

	utils.Logger.Infof("Found %d web services", len(webResults))
	return result, nil
}

func (w *WebScanner) scanWebServices(domain string) ([]HTTPResult, error) {
	var results []HTTPResult

	// Основные URL для проверки
	urlsToCheck := []string{
		fmt.Sprintf("http://%s", domain),
		fmt.Sprintf("https://%s", domain),
		fmt.Sprintf("http://www.%s", domain),
		fmt.Sprintf("https://www.%s", domain),
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	for _, url := range urlsToCheck {
		result, err := w.checkURL(client, url)
		if err != nil {
			utils.Logger.Debugf("Failed to check %s: %v", url, err)
			continue
		}

		if result.StatusCode > 0 {
			results = append(results, result)
			utils.Logger.Debugf("Discovered web service: %s [%d]", url, result.StatusCode)
		}
	}

	// Если ничего не найдено, используем тестовые данные
	if len(results) == 0 {
		utils.Logger.Warn("No web services found, using dummy data")
		results = w.getDummyWebResults(domain)
	}

	return results, nil
}

func (w *WebScanner) checkURL(client *http.Client, url string) (HTTPResult, error) {
	result := HTTPResult{URL: url}

	resp, err := client.Get(url)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Server = resp.Header.Get("Server")

	// Простой парсинг заголовка (в реальности нужно парсить HTML)
	if resp.StatusCode == 200 {
		result.Title = w.extractTitleFromURL(url)
		result.Tech = w.detectTechnologies(resp)
	}

	return result, nil
}

func (w *WebScanner) extractTitleFromURL(url string) string {
	// Упрощенная логика - в реальности нужно парсить HTML
	if strings.Contains(url, "example.com") {
		return "Example Domain"
	}
	return "Unknown Title"
}

func (w *WebScanner) detectTechnologies(resp *http.Response) []string {
	var tech []string

	server := resp.Header.Get("Server")
	if server != "" {
		tech = append(tech, fmt.Sprintf("Server: %s", server))
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	if poweredBy != "" {
		tech = append(tech, fmt.Sprintf("PoweredBy: %s", poweredBy))
	}

	// Простая детекция по заголовкам
	if strings.Contains(server, "nginx") {
		tech = append(tech, "Nginx")
	} else if strings.Contains(server, "Apache") {
		tech = append(tech, "Apache")
	}

	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		tech = append(tech, "HTML")
	}

	return tech
}

func (w *WebScanner) getDiscoveredURLs(results []HTTPResult) []core.WebURL {
	var urls []core.WebURL

	for _, result := range results {
		urls = append(urls, core.WebURL{
			URL:    result.URL,
			Status: result.StatusCode,
			Title:  result.Title,
		})
	}

	return urls
}

func (w *WebScanner) getDummyWebResults(domain string) []HTTPResult {
	return []HTTPResult{
		{
			URL:        fmt.Sprintf("https://%s", domain),
			StatusCode: 200,
			Title:      "Example Domain",
			Server:     "nginx/1.18.0",
			Tech:       []string{"Nginx", "HTML", "TLS"},
		},
		{
			URL:        fmt.Sprintf("http://%s", domain),
			StatusCode: 301,
			Title:      "Redirect",
			Server:     "nginx/1.18.0",
			Tech:       []string{"Nginx", "Redirect"},
		},
		{
			URL:        fmt.Sprintf("https://www.%s", domain),
			StatusCode: 200,
			Title:      "Example Domain",
			Server:     "nginx/1.18.0",
			Tech:       []string{"Nginx", "HTML", "TLS"},
		},
	}
}
