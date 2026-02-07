package extractor

import (
	"io"

	"github.com/xuri/excelize/v2"
)

// ExcelScanner implements scanning for Excel files
type ExcelScanner struct{}

func (s *ExcelScanner) Scan(reader io.Reader) ([]Match, error) {
	// Excelize supports reading from a reader
	f, err := excelize.OpenReader(reader)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []Match

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

			// Join columns to form a "line" for regex or check cell by cell
			// checking cell by cell is safer against splitting PII across cells
			for colIdx, cellValue := range row {
				if cellValue == "" {
					continue
				}

				// Check IBAN
				if found := IBANRegex.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypeIBAN,
						Value:   found,
						Snippet: cellValue,     // Context is the cell itself
						Offset:  int64(rowIdx), // Use row index as offset
					})
				}

				// Check Email
				if found := EmailRegex.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypeEmail,
						Value:   found,
						Snippet: cellValue,
						Offset:  int64(rowIdx),
					})
				}

				// Check Phone
				if found := PhoneRegex.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypePhone,
						Value:   found,
						Snippet: cellValue,
						Offset:  int64(rowIdx),
					})
				}

				// Check Identity Keywords
				if found := IdentityKeywords.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypeIdentity,
						Value:   found,
						Snippet: cellValue,
						Offset:  int64(rowIdx),
					})
				}

				// Check Financial Keywords
				if found := FinancialKeywords.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypeFinancial,
						Value:   found,
						Snippet: cellValue,
						Offset:  int64(rowIdx),
					})
				}

				// Check ID Keywords
				if found := IDKeywords.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypeID,
						Value:   found,
						Snippet: cellValue,
						Offset:  int64(rowIdx),
					})
				}

				// Check Sensitive Keywords
				if found := SensitiveKeywords.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypeSensitive,
						Value:   found,
						Snippet: cellValue,
						Offset:  int64(rowIdx),
					})
				}

				// Check Name
				if found := NameRegex.FindString(cellValue); found != "" {
					matches = append(matches, Match{
						Type:    TypeName,
						Value:   found,
						Snippet: cellValue,
						Offset:  int64(rowIdx),
					})
				}

				// Avoid infinite loops or massive memory usage on extremely wide sheets
				if colIdx > 1000 {
					break
				}
			}
		}
	}

	return matches, nil
}
