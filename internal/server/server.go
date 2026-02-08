package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/digimosa/ai-gdpr-scan/internal/config"
	"github.com/digimosa/ai-gdpr-scan/internal/models"
	"github.com/digimosa/ai-gdpr-scan/internal/reporting"
	"github.com/digimosa/ai-gdpr-scan/internal/scanner"
	"github.com/digimosa/ai-gdpr-scan/internal/storage"
	"github.com/digimosa/ai-gdpr-scan/internal/templates"
	"github.com/digimosa/ai-gdpr-scan/internal/whitelist"
)

type Server struct {
	cfg       *config.Config
	report    *reporting.Report
	whitelist *whitelist.Whitelist
	mu        sync.RWMutex
	scanning  bool
	status    string
}

func NewServer(cfg *config.Config, report *reporting.Report, wl *whitelist.Whitelist) *Server {
	return &Server{
		cfg:       cfg,
		report:    report,
		whitelist: wl,
	}
}

func (s *Server) Start(addr string) error {
	http.HandleFunc("/", s.handleDashboard)
	http.HandleFunc("/api/scans", s.handleListScans) // JSON list of scans
	http.HandleFunc("/api/scans/", s.handleGetScan)  // JSON detail of a scan
	http.HandleFunc("/scan", s.handleScan)           // Trigger new scan
	http.HandleFunc("/logs/ai", s.handleAILogs)      // Stream/Get AI logs
	http.HandleFunc("/whitelist", s.handleWhitelist)

	log.Printf("Starting report server at http://%s", addr)
	return http.ListenAndServe(addr, nil)
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	scans, err := storage.GetAllScans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/scans/")
	scan, err := storage.GetScanByID(id)
	if err != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func (s *Server) handleAILogs(w http.ResponseWriter, r *http.Request) {
	// Read last N lines from log file
	content, err := os.ReadFile("ai_debug.log")
	if err != nil {
		http.Error(w, "Log file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(content)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	scanning := s.scanning
	s.mu.RUnlock()

	if scanning {
		fmt.Fprint(w, templates.LoadingHTML)
		return
	}

	// For now, render the static dashboard, but we should make it dynamic
	// Let's render the detailed report of the LATEST scan by default if user hits /
	// But really we want a "History" view.
	// For this step, let's keep it simple: List of scans

	// Check if ID param is present?
	keys, ok := r.URL.Query()["id"]
	if !ok || len(keys[0]) < 1 {
		// Show list of scans (Dashboard)
		s.renderHistory(w)
		return
	}

	// Show detailed report for specific ID
	scanID := keys[0]
	scan, err := storage.GetScanByID(scanID)
	if err != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	// Need to render the report template with this data
	// Convert storage model to report model
	reportData := convertToReport(scan)
	if err := reportData.RenderHTML(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) renderHistory(w http.ResponseWriter) {
	// Fetch all scans
	scans, _ := storage.GetAllScans()
	// Render a simple HTML list (we can improve this template later)

	// Use a new template or inline HTML for now
	html := `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <title>Scan History</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>body { background-color: #0b0f19; color: #fff; }</style>
</head>
<body class="p-8 max-w-7xl mx-auto font-sans">
    <div class="flex justify-between items-center mb-8">
        <h1 class="text-3xl font-bold">Scan History</h1>
        <div class="flex gap-4">
             <a href="/logs/ai" target="_blank" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm">View AI Logs</a>
             <form action="/scan" method="POST" class="inline">
                <input type="text" name="path" placeholder="/path/to/scan" class="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-white" required value=".">
                <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded text-sm font-bold">New Scan</button>
            </form>
        </div>
    </div>
    
    <div class="grid gap-4">
    `
	for _, scan := range scans {
		statusColor := "text-yellow-400"
		if scan.Status == "Completed" {
			statusColor = "text-green-400"
		}
		if scan.Status == "Failed" {
			statusColor = "text-red-400"
		}

		html += fmt.Sprintf(`
        <div class="p-6 bg-gray-800/50 border border-white/10 rounded-xl hover:bg-gray-800 transition block">
            <div class="flex justify-between items-center">
                <div>
                    <h3 class="text-lg font-semibold">%s</h3>
                    <p class="text-sm text-gray-400">%s</p>
                </div>
                <div class="text-right">
                    <p class="text-sm %s font-bold">%s</p>
                    <p class="text-xs text-gray-500">%d findings</p>
                    <a href="/?id=%d" class="inline-block mt-2 text-blue-400 hover:text-blue-300 text-sm">View Report &rarr;</a>
                </div>
            </div>
        </div>`, scan.RootPath, scan.StartTime.Format("Jan 02 15:04"), statusColor, scan.Status, scan.TotalFindings, scan.ID)
	}
	html += `</div></body></html>`
	fmt.Fprint(w, html)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.FormValue("path")
	if path == "" {
		path = "."
	}

	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		http.Error(w, "Scan already in progress", http.StatusConflict)
		return
	}
	s.scanning = true
	s.mu.Unlock()

	// Update config path
	s.cfg.RootPath = path

	go func() {
		defer func() {
			s.mu.Lock()
			s.scanning = false
			s.mu.Unlock()
		}()

		log.Printf("Starting web-triggered scan on: %s", path)
		scanner := scanner.NewScanner(s.cfg)
		scanner.Whitelist = s.whitelist // Share whitelist
		scanner.Start()
		scanner.Wait()

		s.mu.Lock()
		s.report = scanner.Report
		s.mu.Unlock()
		log.Println("Web-triggered scan finished")
	}()

	// Redirect to status/home
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Value string `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Value == "" {
		http.Error(w, "Value cannot be empty", http.StatusBadRequest)
		return
	}

	if err := s.whitelist.Add(req.Value); err != nil {
		log.Printf("[ERROR] failed to add to whitelist: %v", err)
		http.Error(w, "Failed to save to whitelist", http.StatusInternalServerError)
		return
	}

	log.Printf("[WHITELIST] Added via web UI: %s", req.Value)
	w.WriteHeader(http.StatusOK)
}

func convertToReport(scan *storage.ScanModel) *reporting.Report {
	report := reporting.NewReport()
	report.Summary.RootPath = scan.RootPath
	report.Summary.StartTime = scan.StartTime
	report.Summary.EndTime = scan.EndTime
	report.Summary.ScanDuration = scan.Duration
	report.Summary.TotalFilesScanned = scan.TotalFiles
	report.Summary.TotalFilesWithPII = scan.PIIFiles
	report.Summary.TotalPIIFound = scan.TotalFindings

	// Convert Findings
	grouped := make(map[string][]models.Finding)

	for _, f := range scan.Findings {
		finding := models.Finding{
			Type:       f.Type,
			Snippet:    f.Value,
			Confidence: f.Confidence,
			Offset:     0,
			Context:    f.Reason,
		}
		grouped[f.FilePath] = append(grouped[f.FilePath], finding)
	}

	for path, findings := range grouped {
		report.AddResult(models.ScanResult{
			FilePath: path,
			Findings: findings,
		})
	}

	return report
}
