package extractor

import (
	"bytes"
	"io"
	"os"

	"github.com/ledongthuc/pdf"
)

// PDFScanner implements scanning for PDF files
type PDFScanner struct{}

func (s *PDFScanner) Scan(reader io.Reader) ([]Match, error) {
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

	var matches []Match

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

		// Reuse logic from TextScanner effectively by treating page content as lines
		// Or perform regex directly on the page string

		// Check IBAN
		if found := IBANRegex.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypeIBAN,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i), // Use page number as offset for PDFs
			})
		}

		// Check Email
		if found := EmailRegex.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypeEmail,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i),
			})
		}

		// Check Phone
		if found := PhoneRegex.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypePhone,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i),
			})
		}

		// Check Identity Keywords
		if found := IdentityKeywords.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypeIdentity,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i),
			})
		}

		// Check Financial Keywords
		if found := FinancialKeywords.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypeFinancial,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i),
			})
		}

		// Check ID Keywords
		if found := IDKeywords.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypeID,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i),
			})
		}

		// Check Sensitive Keywords
		if found := SensitiveKeywords.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypeSensitive,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i),
			})
		}

		// Check Name
		if found := NameRegex.FindString(content); found != "" {
			matches = append(matches, Match{
				Type:    TypeName,
				Value:   found,
				Snippet: getSnippet(content, found),
				Offset:  int64(i),
			})
		}
	}

	return matches, nil
}
