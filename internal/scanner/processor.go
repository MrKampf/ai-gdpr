package scanner

import (
	"fmt"
	"time"

	"github.com/digimosa/ai-gdpr-scan/internal/storage"
)

func (s *Scanner) processResults() {
	// Simple logger for now, can be expanded to write to CSV/JSON
	count := 0
	start := time.Now()

	for res := range s.results {
		count++

		// Add to report regardless of findings (tracks total files scanned)
		s.Report.AddResult(res)

		// Save PII to DB if Scan ID exists
		if s.ScanModelID != 0 && len(res.Findings) > 0 {
			for _, f := range res.Findings {
				// We don't have file path in Finding struct directly, need to check how it's structured
				// ScanResult has FilePath.
				// f.Snippet is the value
				// f.Context is the AI reason
				if f.Confidence == 0 {
					fmt.Printf("[DEBUG-ZERO-CONF] Saving %s finding for %s with 0 confidence! (Type: %s)\n", f.Type, res.FilePath, f.Type)
				}
				_ = storage.SaveFinding(s.ScanModelID, res.FilePath, f.Type, f.Snippet, f.Context, f.Confidence)
			}
		}

		if res.Error != nil {
			// Log error if verbose
			continue
		}
		if len(res.Findings) > 0 {
			fmt.Printf("[FOUND] %s: %d potential PII matches\n", res.FilePath, len(res.Findings))
			for _, f := range res.Findings {
				fmt.Printf("  - %s (Confidence: %.2f)\n", f.Type, f.Confidence)
			}
		}

		if count%1000 == 0 {
			fmt.Printf("Processed %d files... (Rate: %.2f files/sec)\n", count, float64(count)/time.Since(start).Seconds())
		}
	}
	s.Report.Finalize() // Finalize timestamps

	// Update Scan Completion Status in DB
	if s.ScanModelID != 0 {
		storage.GetScanByID(fmt.Sprintf("%d", s.ScanModelID)) // Reload? Or just update fields
		// We need a helper to update by ID directly or retrieve first
		if scan, err := storage.GetScanByID(fmt.Sprintf("%d", s.ScanModelID)); err == nil {
			storage.CompleteScan(scan, s.Report.Summary.TotalFilesScanned, s.Report.Summary.TotalFilesWithPII, s.Report.Summary.TotalPIIFound)
		}
	}

	close(s.done)
}
