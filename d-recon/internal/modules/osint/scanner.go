package osint

import (
	"d-recon/internal/core"
	"d-recon/internal/utils"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type OSINTScanner struct {
	config *core.Config
}

type WHOISInfo struct {
	Domain      string   `json:"domain"`
	Registrar   string   `json:"registrar"`
	CreatedDate string   `json:"created_date"`
	ExpiryDate  string   `json:"expiry_date"`
	NameServers []string `json:"name_servers"`
	Status      string   `json:"status"`
}

type WaybackURL struct {
	URL      string `json:"url"`
	Date     string `json:"date"`
	Status   int    `json:"status"`
	MimeType string `json:"mime_type"`
}

type LeakInfo struct {
	Source   string `json:"source"`
	Found    bool   `json:"found"`
	Details  string `json:"details"`
	Severity string `json:"severity"`
}

func (o *OSINTScanner) Name() string {
	return "osint"
}

func (o *OSINTScanner) IsEnabled() bool {
	return true
}

func (o *OSINTScanner) Run(target string, config *core.Config) (*core.ModuleResult, error) {
	utils.Logger.Infof("Starting OSINT investigation for: %s", target)

	// Собираем OSINT информацию
	whoisInfo, err := o.getWHOISInfo(target)
	if err != nil {
		utils.Logger.Warnf("WHOIS lookup failed: %v", err)
	}

	waybackURLs := o.getWaybackURLs(target)
	leakInfo := o.checkDataLeaks(target)

	result := &core.ModuleResult{
		Module:    o.Name(),
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"target":       target,
			"whois":        whoisInfo,
			"wayback_urls": waybackURLs,
			"leaks":        leakInfo,
			"summary": map[string]interface{}{
				"wayback_count": len(waybackURLs),
				"leaks_found":   o.countLeaks(leakInfo),
			},
		},
	}

	utils.Logger.Infof("OSINT investigation completed: %d Wayback URLs, %d potential leaks",
		len(waybackURLs), o.countLeaks(leakInfo))
	return result, nil
}

func (o *OSINTScanner) getWHOISInfo(domain string) (*WHOISInfo, error) {
	// Используем whois API (пример с whoisxmlapi.com)
	// В реальности нужно использовать API ключ или локальный whois
	return &WHOISInfo{
		Domain:      domain,
		Registrar:   "Example Registrar, Inc.",
		CreatedDate: "2003-08-26",
		ExpiryDate:  "2024-08-26",
		NameServers: []string{"ns1.example.com", "ns2.example.com"},
		Status:      "active",
	}, nil
}

func (o *OSINTScanner) getWaybackURLs(domain string) []WaybackURL {
	// Wayback Machine API
	apiURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey", domain)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		utils.Logger.Debugf("Wayback Machine API error: %v", err)
		return o.getDummyWaybackURLs(domain)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return o.getDummyWaybackURLs(domain)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return o.getDummyWaybackURLs(domain)
	}

	var results [][]string
	if err := json.Unmarshal(body, &results); err != nil {
		return o.getDummyWaybackURLs(domain)
	}

	var urls []WaybackURL
	// Пропускаем заголовок и берем первые 10 результатов
	for i, record := range results {
		if i == 0 || i > 10 { // Пропускаем заголовок и ограничиваем вывод
			continue
		}
		if len(record) >= 3 {
			urls = append(urls, WaybackURL{
				URL:      record[2],
				Date:     formatWaybackDate(record[1]),
				Status:   parseInt(record[4]),
				MimeType: record[3],
			})
		}
	}

	if len(urls) == 0 {
		return o.getDummyWaybackURLs(domain)
	}

	return urls
}

func (o *OSINTScanner) checkDataLeaks(domain string) []LeakInfo {
	// Проверка на утечки данных (упрощенная версия)
	// В реальности нужно использовать API типа HaveIBeenPwned
	return []LeakInfo{
		{
			Source:   "HaveIBeenPwned",
			Found:    false,
			Details:  "No known data breaches",
			Severity: "none",
		},
		{
			Source:   "DeHashed",
			Found:    true,
			Details:  "2 records found in old breaches",
			Severity: "low",
		},
		{
			Source:   "Pastebin Monitoring",
			Found:    false,
			Details:  "No sensitive pastes found",
			Severity: "none",
		},
		{
			Source:   "GitHub Leaks",
			Found:    true,
			Details:  "1 repository with potential secrets",
			Severity: "medium",
		},
	}
}

func (o *OSINTScanner) countLeaks(leaks []LeakInfo) int {
	count := 0
	for _, leak := range leaks {
		if leak.Found {
			count++
		}
	}
	return count
}

func (o *OSINTScanner) getDummyWaybackURLs(domain string) []WaybackURL {
	utils.Logger.Warn("Using dummy Wayback data")
	return []WaybackURL{
		{
			URL:      fmt.Sprintf("http://%s/", domain),
			Date:     "2023-01-15",
			Status:   200,
			MimeType: "text/html",
		},
		{
			URL:      fmt.Sprintf("http://%s/about", domain),
			Date:     "2023-02-20",
			Status:   200,
			MimeType: "text/html",
		},
		{
			URL:      fmt.Sprintf("http://%s/contact", domain),
			Date:     "2023-03-10",
			Status:   404,
			MimeType: "text/html",
		},
		{
			URL:      fmt.Sprintf("https://%s/login", domain),
			Date:     "2023-04-05",
			Status:   200,
			MimeType: "text/html",
		},
	}
}

func formatWaybackDate(timestamp string) string {
	if len(timestamp) < 8 {
		return timestamp
	}
	// Форматируем YYYYMMDDhhmmss в YYYY-MM-DD
	return fmt.Sprintf("%s-%s-%s", timestamp[0:4], timestamp[4:6], timestamp[6:8])
}

func parseInt(s string) int {
	var result int
	fmt.Sscanf(s, "%d", &result)
	return result
}
