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

	_ "embed"
	html_template "html/template"
)

//go:embed templates/dashboard.html
var dashboardHTML string

type Server struct {
	cfg       *config.Config
	report    *reporting.Report
	whitelist *whitelist.Whitelist
	mu        sync.RWMutex
	scanning  bool
	status    string
	tmpl      *html_template.Template
}

func NewServer(cfg *config.Config, report *reporting.Report, wl *whitelist.Whitelist) *Server {
	tmpl := html_template.Must(html_template.New("dashboard").Parse(dashboardHTML))

	return &Server{
		cfg:       cfg,
		report:    report,
		whitelist: wl,
		tmpl:      tmpl,
	}
}

func (s *Server) Start(addr string) error {
	http.HandleFunc("/", s.handleDashboard)
	http.HandleFunc("/api/scans", s.handleListScans) // JSON list of scans
	http.HandleFunc("/api/scans/", s.handleGetScan)  // JSON detail of a scan
	http.HandleFunc("/scan", s.handleScan)           // Trigger new scan
	http.HandleFunc("/logs/ai", s.handleAILogs)      // Stream/Get AI logs
	http.HandleFunc("/whitelist", s.handleWhitelist)
	http.HandleFunc("/feedback", s.handleFeedback) // Feedback API

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
	s.mu.RLock()
	// Fetch all scans
	scans, _ := storage.GetAllScans()
	s.mu.RUnlock()

	// Calculate stats
	var totalFindings int64
	var totalPIIFiles int64
	var successCount int

	for _, s := range scans {
		totalFindings += s.TotalFindings
		totalPIIFiles += int64(s.PIIFiles)
		if s.Status == "Completed" {
			successCount++
		}
	}

	data := struct {
		Scans         []storage.ScanModel
		TotalScans    int
		TotalFindings int64
		TotalPIIFiles int64
		SuccessRate   int
	}{
		Scans:         scans,
		TotalScans:    len(scans),
		TotalFindings: totalFindings,
		TotalPIIFiles: totalPIIFiles,
		SuccessRate:   0,
	}

	if len(scans) > 0 {
		data.SuccessRate = (successCount * 100) / len(scans)
	}

	w.Header().Set("Content-Type", "text/html")
	if err := s.tmpl.Execute(w, data); err != nil {
		log.Printf("Template render error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
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

	fastMode := r.FormValue("fast_mode") == "on"
	aiEnabled := r.FormValue("ai_enabled") == "on"

	s.mu.Lock()
	if s.scanning {
		s.mu.Unlock()
		http.Error(w, "Scan already in progress", http.StatusConflict)
		return
	}
	s.scanning = true
	s.mu.Unlock()

	// Update config
	s.cfg.RootPath = path
	s.cfg.FastMode = fastMode
	s.cfg.DisableAI = !aiEnabled

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

func (s *Server) handleFeedback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID       string `json:"id"`
		Feedback string `json:"feedback"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.ID == "" || (req.Feedback != "Correct" && req.Feedback != "Incorrect") {
		http.Error(w, "Invalid ID or Feedback value", http.StatusBadRequest)
		return
	}

	if err := storage.UpdateFeedback(req.ID, req.Feedback); err != nil {
		log.Printf("[ERROR] failed to update feedback: %v", err)
		http.Error(w, "Failed to save feedback", http.StatusInternalServerError)
		return
	}

	log.Printf("[FEEDBACK] Finding %s marked as %s", req.ID, req.Feedback)
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
			ID:         f.ID,
			Type:       f.Type,
			Snippet:    f.Value,
			Confidence: f.Confidence,
			Offset:     0,
			Context:    f.Reason,
			Feedback:   f.Feedback,
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
