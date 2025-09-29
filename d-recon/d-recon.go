package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Global configuration (simplified)
var config ReconConfig

// =================================================================================
// 1. СТРУКТУРЫ ДАННЫХ (Data Structures)
// =================================================================================

// ReconConfig - Общая конфигурация сканирования, заполняется флагами CLI
type ReconConfig struct {
	Target          string
	Profile         string
	Modules         []string
	SubdomainTools  []string
	WebTools        []string
	PortScanMode    string
	ConfigFilePath  string
	RateLimit       int
	Timeout         int
	Retries         int
	WebDepth        int
	OSINTDepth      int
	OutputDir       string
	OutputFormat    string // 'json', 'md', 'html', 'pdf'
	NoConsoleOutput bool
	Verbose         bool
	Debug           bool
	// IPs добавлен для хранения разрешенных адресов.
	IPs []string
}

// ReconResult - Агрегированные результаты разведки
type ReconResult struct {
	Target     string
	IPs        []string
	Duration   string
	Subdomains []string
	// Key: IP, Value: List of ports (e.g., "80/tcp (http)")
	OpenPorts       map[string][]string
	Vulnerabilities []string
}

// PortScanResult - Результат сканирования одного IP (для nmap)
type PortScanResult struct {
	IP    string
	Ports []string
}

// =================================================================================
// 2. ЯДРО (Core Logic)
// =================================================================================

func main() {
	// Имитация парсинга флагов и установки config.
	// Используем значения по умолчанию для тестирования.
	config = ReconConfig{
		Target:    "scanme.nmap.org", // Цель изменена на безопасный тестовый домен
		Profile:   "quick",
		Modules:   []string{"subdomains", "ports", "osint"},
		OutputDir: "d-recon_reports",
		// Установим формат HTML для генерации отчета по умолчанию
		OutputFormat:    "html",
		Verbose:         true,
		Debug:           true,
		NoConsoleOutput: false,
	}

	if config.Target == "" {
		logError("Цель сканирования (-t) не указана. Завершение.")
		return
	}

	logInfo("Запуск разведки для цели: %s (Профиль: %s)", config.Target, config.Profile)

	executeRecon()
}

// ResolveTarget - Имитация разрешения доменного имени в IP-адреса
func ResolveTarget() ([]string, error) {
	// ЗАГЛУШКА: В реальном приложении здесь будет вызов DNS-резолвера
	// Обновлены заглушки для новой цели
	if config.Target == "scanme.nmap.org" {
		return []string{"45.33.32.156"}, nil
	} else if config.Target == "kinopoisk.ru" {
		return []string{"213.180.199.9"}, nil
	}
	return []string{}, fmt.Errorf("не удалось разрешить цель: %s", config.Target)
}

// executeRecon - Основной цикл разведки
func executeRecon() {
	startTime := time.Now()
	results := &ReconResult{
		Target:    config.Target,
		OpenPorts: make(map[string][]string),
	}

	// Разрешение IP (Шаг 1)
	ips, err := ResolveTarget()
	if err != nil {
		logError("Ошибка разрешения цели: %v", err)
		return
	}

	// Сохраняем IP-адреса в конфиге
	config.IPs = ips
	results.IPs = ips
	logInfo("Разрешенные IPv4: %s", strings.Join(ips, ", "))

	var wg sync.WaitGroup
	resultsChan := make(chan *ReconResult, len(config.Modules))

	for _, moduleName := range config.Modules {
		wg.Add(1)
		// Запуск модуля в отдельной горутине
		go runModule(moduleName, resultsChan, &wg)
	}

	wg.Wait()
	close(resultsChan)

	// Агрегация результатов
	for res := range resultsChan {
		results.Subdomains = append(results.Subdomains, res.Subdomains...)
		results.Vulnerabilities = append(results.Vulnerabilities, res.Vulnerabilities...)
		for ip, ports := range res.OpenPorts {
			results.OpenPorts[ip] = append(results.OpenPorts[ip], ports...)
		}
	}

	// Постобработка и вывод
	duration := time.Since(startTime).Round(time.Second).String()
	results.Duration = duration

	logDone("Разведка завершена. Длительность: %s", results.Duration)

	// Вывод результатов в консоль
	printResults(results)

	// Экспорт результатов в файл (теперь активен)
	exportResults(results)
}

// runModule - Выполняет логику для одного модуля разведки
func runModule(moduleName string, resultsChan chan *ReconResult, wg *sync.WaitGroup) {
	defer wg.Done()

	moduleResults := &ReconResult{OpenPorts: make(map[string][]string)}

	switch moduleName {
	case "subdomains":
		logInfo("Запуск модуля 'subdomains'...")
		time.Sleep(1 * time.Second) // Имитация работы

		// Заглушка, зависящая от целевого домена
		subdomains := []string{
			fmt.Sprintf("www.%s", config.Target),
			fmt.Sprintf("api.%s", config.Target),
		}
		if config.Target == "scanme.nmap.org" {
			subdomains = []string{
				"test.scanme.nmap.org",
			}
		} else if config.Target == "kinopoisk.ru" {
			subdomains = []string{
				"www.kinopoisk.ru",
				"api.kinopoisk.ru",
			}
		}

		moduleResults.Subdomains = subdomains
		logDone("Модуль 'subdomains' завершен. Найдено %d субдоменов.", len(moduleResults.Subdomains))

	case "ports":
		logInfo("Запуск модуля 'ports'...")

		var portsWG sync.WaitGroup
		// Канал для сбора результатов сканирования портов с каждого IP
		portsChan := make(chan []PortScanResult, len(config.IPs))

		if len(config.IPs) == 0 {
			logWarn("Модуль 'ports' пропущен: не найдено IP-адресов.")
			return
		}

		for _, ip := range config.IPs {
			portsWG.Add(1)
			// Корректный захват переменной ip для горутины
			go func(currentIP string) {
				defer portsWG.Done()

				// Имитация: в реальном приложении здесь будет ExecuteTool("nmap", args)
				if config.Debug {
					logVerbose("Запуск Nmap для IP: %s", currentIP)
				}

				// Имитация результатов, зависящая от IP
				var parsedResults []PortScanResult
				if currentIP == "45.33.32.156" { // IP scanme.nmap.org
					parsedResults = []PortScanResult{
						{IP: currentIP, Ports: []string{"22/tcp (ssh)", "80/tcp (http)", "443/tcp (https)", "9929/tcp (nping)"}},
					}
				} else if currentIP == "213.180.199.9" { // IP kinopoisk.ru
					parsedResults = []PortScanResult{
						{IP: currentIP, Ports: []string{"22/tcp (ssh)", "80/tcp (http)", "443/tcp (https)"}},
					}
				}

				portsChan <- parsedResults

			}(ip) // Передаем 'ip' как аргумент, чтобы избежать захвата по ссылке
		}

		portsWG.Wait()
		close(portsChan)

		// Агрегация результатов сканирования портов
		for resList := range portsChan {
			for _, res := range resList {
				moduleResults.OpenPorts[res.IP] = res.Ports
			}
		}

		totalPorts := 0
		for _, ports := range moduleResults.OpenPorts {
			totalPorts += len(ports)
		}

		logDone("Модуль 'ports' завершен. Найдено %d открытых портов на %d IP-адресах.", totalPorts, len(config.IPs))

	case "osint":
		logInfo("Запуск модуля 'osint'...")
		time.Sleep(500 * time.Millisecond) // Имитация работы

		vulns := []string{"OSINT: найдена устаревшая запись WHOIS"}
		if config.Target == "scanme.nmap.org" {
			vulns = []string{"OSINT: домен является тестовым", "OSINT: контактная информация скрыта (privacy protected)"}
		}

		moduleResults.Vulnerabilities = vulns
		logDone("Модуль 'osint' завершен.")

	default:
		logWarn("Неизвестный модуль: %s. Пропуск.", moduleName)
	}

	resultsChan <- moduleResults
}

// ExecuteTool - Имитация выполнения внешней утилиты (nmap, subfinder и т.д.)
func ExecuteTool(toolName string, path string, args []string) (string, error) {
	if config.Debug {
		logVerbose("Выполнение: %s %s", toolName, strings.Join(args, " "))
	}
	// ЗАГЛУШКА
	return fmt.Sprintf("Mock output for %s", toolName), nil
}

// ParseNmapXML - Заглушка для парсинга вывода Nmap
func ParseNmapXML(output string, ip string) []PortScanResult {
	// ЗАГЛУШКА
	return []PortScanResult{
		{
			IP:    ip,
			Ports: []string{"80/tcp (http)", "443/tcp (https)"},
		},
	}
}

// getNmapArgs - Заглушка для получения аргументов Nmap
func getNmapArgs(ip string) []string {
	// ЗАГЛУШКА
	return []string{"-sT", "-p-", ip}
}

// =================================================================================
// 3. УТИЛИТЫ И ВЫВОД (Utilities and Output)
// =================================================================================

// printResults - Выводит агрегированные результаты в консоль
func printResults(results *ReconResult) {
	if config.NoConsoleOutput {
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Printf("ЦЕЛЬ: %s\n", results.Target)
	fmt.Printf("IP-адреса: %s\n", strings.Join(results.IPs, ", "))
	fmt.Printf("Длительность: %s\n", results.Duration)
	fmt.Println(strings.Repeat("=", 60))

	if len(results.Subdomains) > 0 {
		fmt.Printf("[+] Найдено %d уникальных субдоменов:\n", len(results.Subdomains))
		for _, sub := range results.Subdomains {
			fmt.Printf("    - %s\n", sub)
		}
		fmt.Println()
	}

	totalPorts := 0
	for _, ports := range results.OpenPorts {
		totalPorts += len(ports)
	}
	if totalPorts > 0 {
		fmt.Printf("[+] Найдено %d открытых портов на %d IP-адресах:\n", totalPorts, len(results.IPs))
		for ip, ports := range results.OpenPorts {
			fmt.Printf("  IP %s:\n", ip)
			for _, port := range ports {
				fmt.Printf("    - %s\n", port)
			}
		}
		fmt.Println()
	}

	if len(results.Vulnerabilities) > 0 {
		fmt.Printf("[!] Обнаружено %d OSINT-фактов / уязвимостей:\n", len(results.Vulnerabilities))
		for _, vuln := range results.Vulnerabilities {
			fmt.Printf("    - %s\n", vuln)
		}
		fmt.Println()
	}
}

// log - Основная функция логирования
func log(level string, format string, a ...interface{}) {
	if config.NoConsoleOutput {
		return
	}
	// Режим DEBUG выводится только если установлен config.Debug
	if level == "DEBUG" && !config.Debug {
		return
	}
	message := fmt.Sprintf(format, a...)
	fmt.Printf("[%s] %s\n", level, message)
}

func logInfo(format string, a ...interface{}) {
	log("INFO", format, a...)
}

func logWarn(format string, a ...interface{}) {
	log("WARN", format, a...)
}

func logError(format string, a ...interface{}) {
	log("ERROR", format, a...)
}

func logDone(format string, a ...interface{}) {
	log("DONE", format, a...)
}

func logVerbose(format string, a ...interface{}) {
	log("DEBUG", format, a...)
}

// =================================================================================
// 4. ГЕНЕРАЦИЯ ОТЧЕТОВ (Report Generation)
// =================================================================================

func exportResults(results *ReconResult) {
	if config.OutputDir == "" {
		logWarn("Папка вывода не указана. Пропуск экспорта.")
		return
	}

	// 1. Создание папки, если она не существует
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		logError("Не удалось создать папку вывода %s: %v", config.OutputDir, err)
		return
	}

	// 2. Определение базового имени файла
	// Здесь используется results.Target, который берется из config.Target,
	// обеспечивая уникальность имени файла для каждой цели.
	filenameBase := fmt.Sprintf("%s_%s", results.Target, time.Now().Format("20060102_150405"))

	outputFormat := strings.ToLower(config.OutputFormat)

	// 3. Генерация и запись в файл
	switch outputFormat {
	case "json":
		data := generateJSONReport(results)
		filePath := fmt.Sprintf("%s/%s.json", config.OutputDir, filenameBase)
		writeFile(filePath, data)
		logDone("Отчет JSON сохранен: %s", filePath)

	case "md", "markdown":
		data := generateMarkdownReport(results)
		filePath := fmt.Sprintf("%s/%s.md", config.OutputDir, filenameBase)
		writeFile(filePath, data)
		logDone("Отчет Markdown сохранен: %s", filePath)

	case "html", "pdf":
		// PDF в Go сложен. Генерируем HTML, оптимизированный для печати.
		data := generateHTMLReport(results)
		filePath := fmt.Sprintf("%s/%s.html", config.OutputDir, filenameBase)
		writeFile(filePath, data)
		logDone("Отчет HTML (для PDF) сохранен: %s", filePath)
		logInfo("Для получения PDF-отчета: откройте HTML-файл и используйте функцию печати браузера ('Сохранить как PDF').")

	default:
		logWarn("Неподдерживаемый формат отчета: %s. Экспорт пропущен.", config.OutputFormat)
	}
}

// writeFile - Вспомогательная функция для записи контента в файл
func writeFile(path string, content string) {
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		logError("Ошибка записи файла %s: %v", path, err)
	}
}

// generateJSONReport - Генерирует JSON-отчет
func generateJSONReport(results *ReconResult) string {
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		logError("Ошибка кодирования JSON: %v", err)
		return ""
	}
	return string(jsonData)
}

// generateMarkdownReport - Генерирует Markdown-отчет
func generateMarkdownReport(results *ReconResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Отчет по разведке: %s\n\n", results.Target))
	sb.WriteString(fmt.Sprintf("**Длительность:** %s\n", results.Duration))
	sb.WriteString(fmt.Sprintf("**IP-адреса:** %s\n", strings.Join(results.IPs, ", ")))
	sb.WriteString("---\n\n")

	// Субдомены
	if len(results.Subdomains) > 0 {
		sb.WriteString("## 1. Обнаруженные субдомены\n\n")
		for _, sub := range results.Subdomains {
			sb.WriteString(fmt.Sprintf("- `%s`\n", sub))
		}
		sb.WriteString("\n")
	}

	// Открытые порты
	if len(results.OpenPorts) > 0 {
		sb.WriteString("## 2. Открытые порты\n\n")
		for ip, ports := range results.OpenPorts {
			sb.WriteString(fmt.Sprintf("### IP: %s\n", ip))
			for _, port := range ports {
				sb.WriteString(fmt.Sprintf("- `%s`\n", port))
			}
			sb.WriteString("\n")
		}
	}

	// Уязвимости/OSINT
	if len(results.Vulnerabilities) > 0 {
		sb.WriteString("## 3. Факты OSINT и уязвимости\n\n")
		for _, vuln := range results.Vulnerabilities {
			sb.WriteString(fmt.Sprintf("* **%s**\n", vuln))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// generateHTMLReport - Генерирует HTML-отчет, оптимизированный для печати/PDF
func generateHTMLReport(results *ReconResult) string {
	var sb strings.Builder

	// HTML-шаблон с Tailwind и стилями для печати (имитация)
	sb.WriteString(`<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Отчет d-recon: `)
	sb.WriteString(results.Target)
	sb.WriteString(`</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @media print {
            body {
                font-size: 10pt;
            }
            .page-break {
                display: block;
                page-break-before: always;
            }
        }
        body {
            font-family: 'Inter', sans-serif;
        }
    </style>
</head>
<body class="bg-gray-50 p-6 md:p-12">
    <div class="max-w-4xl mx-auto bg-white shadow-xl rounded-xl p-8">
        <h1 class="text-3xl font-extrabold text-blue-800 border-b-4 border-blue-200 pb-2 mb-6">Отчет по разведке безопасности</h1>
        
        <!-- Сводка -->
        <div class="space-y-2 mb-8 p-4 bg-blue-50 rounded-lg border border-blue-100">
            <p class="text-lg font-semibold text-gray-700">Цель: <span class="text-blue-900 font-extrabold">`)
	sb.WriteString(results.Target)
	sb.WriteString(`</span></p>
            <p class="text-sm text-gray-600">IP-адреса: <span class="font-mono text-xs bg-gray-200 px-2 py-0.5 rounded">`)
	sb.WriteString(strings.Join(results.IPs, ", "))
	sb.WriteString(`</span></p>
            <p class="text-sm text-gray-600">Длительность сканирования: <span class="font-medium text-blue-600">`)
	sb.WriteString(results.Duration)
	sb.WriteString(`</span></p>
        </div>

        <!-- 1. Субдомены -->
        <h2 class="text-2xl font-bold text-gray-800 mt-8 mb-4 border-b-2 pb-1">1. Обнаруженные субдомены (` + fmt.Sprintf("%d", len(results.Subdomains)) + `)</h2>
        <ul class="list-disc ml-6 space-y-1 text-gray-700">`)
	if len(results.Subdomains) == 0 {
		sb.WriteString(`<li class="text-sm text-gray-500">Субдомены не найдены.</li>`)
	} else {
		for _, sub := range results.Subdomains {
			sb.WriteString(fmt.Sprintf(`<li><span class="font-mono text-sm bg-gray-100 px-2 py-0.5 rounded">%s</span></li>`, sub))
		}
	}
	sb.WriteString(`</ul>

        <!-- 2. Открытые порты -->
        <h2 class="text-2xl font-bold text-gray-800 mt-8 mb-4 border-b-2 pb-1">2. Открытые порты</h2>
        <div class="space-y-6">`)
	if len(results.OpenPorts) == 0 {
		sb.WriteString(`<p class="text-sm text-gray-500 p-4 border rounded-lg bg-yellow-50">Открытые порты не найдены.</p>`)
	} else {
		for ip, ports := range results.OpenPorts {
			sb.WriteString(fmt.Sprintf(`<div class="border p-4 rounded-lg bg-white shadow-sm">
                <h3 class="text-lg font-semibold text-gray-800 mb-3">IP-адрес: <span class="font-mono bg-gray-200 px-2 rounded">%s</span></h3>
                <ul class="space-y-1">`, ip))
			for _, port := range ports {
				sb.WriteString(fmt.Sprintf(`<li class="flex items-center text-sm text-green-700">
                    <svg class="w-4 h-4 mr-2 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
                    %s
                </li>`, port))
			}
			sb.WriteString(`</ul></div>`)
		}
	}
	sb.WriteString(`</div>

        <!-- 3. Уязвимости / OSINT -->
        <h2 class="text-2xl font-bold text-gray-800 mt-8 mb-4 border-b-2 pb-1">3. Факты OSINT и уязвимости</h2>
        <ul class="list-disc ml-6 space-y-2 text-gray-700">`)
	if len(results.Vulnerabilities) == 0 {
		sb.WriteString(`<li class="text-sm text-gray-500">Уязвимости и значимые факты OSINT не найдены.</li>`)
	} else {
		for _, vuln := range results.Vulnerabilities {
			sb.WriteString(fmt.Sprintf(`<li class="text-red-600 font-medium">%s</li>`, vuln))
		}
	}
	sb.WriteString(`</ul>

        <div class="page-break"></div> 
        <p class="text-xs text-gray-400 text-center mt-10 border-t pt-4">Отчет сгенерирован d-recon - `)
	sb.WriteString(time.Now().Format("02.01.2006 15:04:05"))
	sb.WriteString(`</p>
    </div>
</body>
</html>`)
	return sb.String()
}
