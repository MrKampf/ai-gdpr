package server

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"github.com/digimosa/ai-gdpr-scan/internal/reporting"
	"github.com/digimosa/ai-gdpr-scan/internal/whitelist"
)

type Server struct {
	report    *reporting.Report
	whitelist *whitelist.Whitelist
	mu        sync.Mutex
}

func NewServer(report *reporting.Report, wl *whitelist.Whitelist) *Server {
	return &Server{
		report:    report,
		whitelist: wl,
	}
}

func (s *Server) Start(addr string) error {
	http.HandleFunc("/", s.handleReport)
	http.HandleFunc("/whitelist", s.handleWhitelist)

	log.Printf("Starting report server at http://%s", addr)
	return http.ListenAndServe(addr, nil)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	// Re-render HTML with latest report data?
	// The report data is static from the scan, but maybe we want to refresh?
	// For now, we just serve the HTML. But wait, `reporting` package generates strings or files.
	// We should probably expose a method to Render HTML directly to a writer.

	w.Header().Set("Content-Type", "text/html")
	if err := s.report.RenderHTML(w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
