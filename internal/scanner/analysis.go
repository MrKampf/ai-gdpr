package scanner

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// scanFile implements the tiered scanning logic
func (s *Scanner) scanFile(path string) models.ScanResult {
	start := time.Now()
	res := models.ScanResult{
		FilePath:  path,
		Timestamp: time.Now(),
	}

	// Get file info
	info, err := os.Stat(path)
	if err != nil {
		res.Error = err
		res.ErrorMsg = err.Error()
		return res
	}
	res.Size = info.Size()

	// Tier 1: Fast Filter (Extensions) via Factory
	scanner, ext, err := s.scannerFactory.GetScannerForFile(path)
	if err != nil {
		// Unsupported extension or other error (e.g. factory rejected it)
		// We just skip it from processing but don't count it as an application error unless path access failed
		return res
	}
	res.FileType = ext

	if s.cfg.Verbose {
		log.Printf("[SCAN] scanning file: %s (%s)", path, ext)
	}

	// Tier 2: Heuristic Scan
	file, err := os.Open(path)
	if err != nil {
		res.Error = err
		res.ErrorMsg = fmt.Sprintf("failed to open file: %v", err)
		if s.cfg.Verbose {
			log.Printf("[ERROR] failed to open file %s: %v", path, err)
		}
		return res
	}
	defer file.Close()

	matches, err := scanner.Scan(file)
	if err != nil {
		res.Error = err
		res.ErrorMsg = fmt.Sprintf("scan failed: %v", err)
		if s.cfg.Verbose {
			log.Printf("[ERROR] scan failed for %s: %v", path, err)
		}
		return res
	}

	if s.cfg.Verbose && len(matches) > 0 {
		log.Printf("[MATCH] %s: found %d potential regex matches", path, len(matches))
	}

	// Optimization: Skip individual snippet validation to reduce AI calls
	// Instead, send the aggregated context once for full analysis if any regex matches are found.
	if len(matches) > 0 {
		if s.cfg.DisableAI {
			// Just add regex matches directly
			for _, m := range matches {
				res.Findings = append(res.Findings, models.Finding{
					Type:       string(m.Type),
					Snippet:    m.Snippet,
					Confidence: 0.5, // Regex only confidence
					Offset:     m.Offset,
				})
			}
		} else {
			s.performAIAnalysis(path, matches, &res)
		}
	}

	res.ScanTime = time.Since(start)
	return res
}

func (s *Scanner) performAIAnalysis(path string, matches []models.Match, res *models.ScanResult) {
	if s.cfg.Verbose {
		log.Printf("[AI] file %s has %d potential matches, sending for bulk analysis...", path, len(matches))
	}

	// Construct context from all regex matches
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("File: %s\nPotential PII Context:\n", filepath.Base(path)))

	// Limit the number of snippets sent to avoid context window explosion
	limit := 50
	if len(matches) < limit {
		limit = len(matches)
	}

	for i := 0; i < limit; i++ {
		m := matches[i]
		sb.WriteString(fmt.Sprintf("- [%s] %s\n", m.Type, m.Snippet))
	}
	fullContext := sb.String()

	// One Single AI Call per file with interesting regex hits
	// Extract unique finding types for prompt customization
	uniqueTypes := make(map[models.FindingType]bool)
	typeList := []models.FindingType{}
	for _, m := range matches {
		if !uniqueTypes[m.Type] {
			uniqueTypes[m.Type] = true
			typeList = append(typeList, m.Type)
		}
	}

	aiFindings, err := s.aiClient.AnalyzeFile(fullContext, typeList)

	if err == nil {
		for _, f := range aiFindings {
			if s.cfg.Verbose {
				log.Printf("[AI-FULL] %s: Found %s - %s", path, f.Type, f.Reason)
			}

			if s.Whitelist.Contains(f.Value) {
				if s.cfg.Verbose {
					log.Printf("[WHITELIST] skipping known value: %s", f.Value)
				}
				continue
			}

			res.Findings = append(res.Findings, models.Finding{
				Type:       f.Type,
				Snippet:    f.Value,
				Confidence: f.Confidence, // AI-provided confidence
				Offset:     0,
				Context:    f.Reason, // Store the AI's explanation here
			})
		}
	} else {
		if s.cfg.Verbose {
			log.Printf("[AI-FULL] Error analyzing file %s: %v", path, err)
		}
		// Fallback: If AI fails, add the raw regex matches with lower confidence so we don't lose them
		for _, m := range matches {
			res.Findings = append(res.Findings, models.Finding{
				Type:       string(m.Type),
				Snippet:    m.Snippet,
				Confidence: 0.5, // Lower confidence because AI didn't verify
				Offset:     m.Offset,
			})
		}
	}
}
