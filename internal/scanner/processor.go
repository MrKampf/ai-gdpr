package scanner

import (
	"fmt"
	"time"
)

func (s *Scanner) processResults() {
	// Simple logger for now, can be expanded to write to CSV/JSON
	count := 0
	start := time.Now()

	for res := range s.results {
		count++

		// Add to report regardless of findings (tracks total files scanned)
		s.Report.AddResult(res)

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
	close(s.done)
}
