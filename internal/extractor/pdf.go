package extractor

import (
	"bytes"
	"io"
	"os"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
	"github.com/ledongthuc/pdf"
)

// PDFScanner implements scanning for PDF files
type PDFScanner struct{}

func (s *PDFScanner) Scan(reader io.Reader) ([]models.Match, error) {
	// ledongthuc/pdf requires an io.ReaderAt and size.
	// Since we are passed an io.Reader, we might need to read it into a buffer
	// or modify the interface to accept a file path or require ReaderAt.
	// For optimal performance with huge PDFs, we should pass file path,
	// but keeping the interface generic (io.Reader) means buffering for this lib.

	// Check if the reader is an *os.File or *bytes.Reader which support ReaderAt
	var readerAt io.ReaderAt
	var size int64

	switch r := reader.(type) {
	case *os.File:
		stat, err := r.Stat()
		if err != nil {
			return nil, err
		}
		readerAt = r
		size = stat.Size()
	case *bytes.Reader:
		readerAt = r
		size = int64(r.Len())
	default:
		// Fallback: Read into memory (Not ideal for large files)
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		readerAt = bytes.NewReader(data)
		size = int64(len(data))
	}

	doc, err := pdf.NewReader(readerAt, size)
	if err != nil {
		return nil, err
	}

	var matches []models.Match

	// Iterate through pages
	// Note: ledongthuc/pdf can be slow on large docs, consider timeouts in calling code
	totalPages := doc.NumPage()

	for i := 1; i <= totalPages; i++ {
		page := doc.Page(i)
		if page.V.IsNull() {
			continue
		}

		content, err := page.GetPlainText(nil)
		if err != nil {
			continue // Skip page on error
		}

		// Use the centralized regex checks
		// Offset is set to page number for PDF context
		// We could try to map byte offset within page, but page number is more useful
		pageFindings := runRegexChecks(content, int64(i))
		matches = append(matches, pageFindings...)
	}

	return matches, nil
}
