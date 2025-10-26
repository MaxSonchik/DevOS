package web

import (
	"d-recon/internal/core"
	"d-recon/internal/utils"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type WebServer struct {
	port    int
	dataDir string
}

type ScanResult struct {
	Target    string                 `json:"target"`
	Timestamp time.Time              `json:"timestamp"`
	Duration  string                 `json:"duration"`
	Modules   map[string]interface{} `json:"modules"`
}

func NewWebServer(port int, dataDir string) *WebServer {
	return &WebServer{
		port:    port,
		dataDir: dataDir,
	}
}

func (w *WebServer) Start() error {
	http.HandleFunc("/", w.handleIndex)
	http.HandleFunc("/api/scans", w.handleScansAPI)
	http.HandleFunc("/api/scan/", w.handleScanAPI)
	http.HandleFunc("/scan/", w.handleScanDetail)

	// Статические файлы
	fs := http.FileServer(http.Dir("web/static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	utils.Logger.Infof("Web interface started on http://localhost:%d", w.port)
	return http.ListenAndServe(fmt.Sprintf(":%d", w.port), nil)
}

func (w *WebServer) handleIndex(wr http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("web/templates/index.html"))
	tmpl.Execute(wr, nil)
}

func (w *WebServer) handleScansAPI(wr http.ResponseWriter, r *http.Request) {
	scans, err := w.getAvailableScans()
	if err != nil {
		http.Error(wr, err.Error(), http.StatusInternalServerError)
		return
	}

	wr.Header().Set("Content-Type", "application/json")
	json.NewEncoder(wr).Encode(scans)
}

func (w *WebServer) handleScanAPI(wr http.ResponseWriter, r *http.Request) {
	target := r.URL.Path[len("/api/scan/"):]
	if target == "" {
		http.Error(wr, "Target required", http.StatusBadRequest)
		return
	}

	result, err := w.loadScanResult(target)
	if err != nil {
		http.Error(wr, err.Error(), http.StatusNotFound)
		return
	}

	wr.Header().Set("Content-Type", "application/json")
	json.NewEncoder(wr).Encode(result)
}

func (w *WebServer) handleScanDetail(wr http.ResponseWriter, r *http.Request) {
	target := r.URL.Path[len("/scan/"):]
	if target == "" {
		http.Error(wr, "Target required", http.StatusBadRequest)
		return
	}

	tmpl := template.Must(template.ParseFiles("web/templates/scan.html"))
	data := map[string]string{"Target": target}
	tmpl.Execute(wr, data)
}

func (w *WebServer) getAvailableScans() ([]string, error) {
	files, err := os.ReadDir(w.dataDir)
	if err != nil {
		return nil, err
	}

	var scans []string
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			scans = append(scans, file.Name()[:len(file.Name())-5]) // Remove .json
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(scans)))
	return scans, nil
}

func (w *WebServer) loadScanResult(target string) (*ScanResult, error) {
	filename := filepath.Join(w.dataDir, target+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var result core.ReconResults
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	// Конвертируем в формат для веб-интерфейса
	modules := make(map[string]interface{})
	for name, module := range result.Modules {
		modules[name] = module.Data
	}

	return &ScanResult{
		Target:    result.Target,
		Timestamp: result.StartTime,
		Duration:  result.EndTime.Sub(result.StartTime).String(),
		Modules:   modules,
	}, nil
}
