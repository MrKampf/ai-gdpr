package extractor

import (
	"io"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
	"github.com/xuri/excelize/v2"
)

// ExcelScanner implements scanning for Excel files
type ExcelScanner struct{}

func (s *ExcelScanner) Scan(reader io.Reader) ([]models.Match, error) {
	// Excelize supports reading from a reader
	f, err := excelize.OpenReader(reader)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []models.Match

	// Get all sheet names
	for _, sheet := range f.GetSheetList() {
		// Use streaming row iterator for memory efficiency
		rows, err := f.Rows(sheet)
		if err != nil {
			continue
		}

		rowIdx := 0
		for rows.Next() {
			rowIdx++
			row, err := rows.Columns()
			if err != nil {
				break
			}

			// Check each cell using centralized regex checks
			// We treat each cell as a small "content" block
			for colIdx, cellValue := range row {
				if cellValue == "" {
					continue
				}

				// Run checks
				findings := runRegexChecks(cellValue, int64(rowIdx))

				// For excel, the snippet is the cell content itself usually,
				// but runRegexChecks generates snippets based on its input.
				// Since input is just cellValue, snippet == cellValue (mostly).
				matches = append(matches, findings...)

				// Avoid infinite loops or massive memory usage on extremely wide sheets
				if colIdx > 1000 {
					break
				}
			}
		}
	}

	return matches, nil
}
