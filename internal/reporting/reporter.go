package reporting

import (
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
	"github.com/digimosa/ai-gdpr-scan/internal/templates"
)

type Summary struct {
	TotalFilesScanned int64         `json:"total_files_scanned"`
	TotalFilesWithPII int64         `json:"total_files_with_pii"`
	TotalPIIFound     int64         `json:"total_pii_found"`
	ScanDuration      time.Duration `json:"scan_duration"`
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
	RootPath          string        `json:"root_path"`
}

type Report struct {
	Summary  Summary             `json:"summary"`
	Findings []models.ScanResult `json:"findings"`
	mu       sync.Mutex
}

func NewReport() *Report {
	return &Report{
		Summary: Summary{
			StartTime: time.Now(),
		},
		Findings: make([]models.ScanResult, 0),
	}
}

func (r *Report) AddResult(res models.ScanResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Summary.TotalFilesScanned++
	if len(res.Findings) > 0 {
		r.Summary.TotalFilesWithPII++
		r.Summary.TotalPIIFound += int64(len(res.Findings))
		r.Findings = append(r.Findings, res)
	}
}

func (r *Report) Finalize() {
	r.Summary.EndTime = time.Now()
	r.Summary.ScanDuration = r.Summary.EndTime.Sub(r.Summary.StartTime)
}

func (r *Report) SaveJSON(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

func (r *Report) SaveHTML(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	return r.RenderHTML(file)
}

func (r *Report) RenderHTML(w io.Writer) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"marshal": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"mul": func(a, b float64) float64 {
			return a * b
		},
		"hasPrefix": strings.HasPrefix,
		"hasSuffix": strings.HasSuffix,
		"parseJSON": func(s string) interface{} {
			var out interface{}
			if err := json.Unmarshal([]byte(s), &out); err != nil {
				return nil
			}
			return out
		},
	}).Parse(templates.ReportHTML)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, r)
}
