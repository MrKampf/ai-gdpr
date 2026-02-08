package extractor

import (
	"io"

	"github.com/digimosa/ai-gdpr-scan/internal/extractor/detectors"
	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// Scanner defines the interface for content scanning
type ContentScanner interface {
	Scan(reader io.Reader) ([]models.Match, error)
}

// TextScanner implements scanning for plain text files
// It now uses chunk-based reading to handle binary/mixed files robustly.
type TextScanner struct{}

func (s *TextScanner) Scan(reader io.Reader) ([]models.Match, error) {
	var matches []models.Match

	// Use a 64KB buffer for chunk-based reading
	const bufSize = 64 * 1024
	buf := make([]byte, bufSize)

	// Overlap window size (max expected PII length)
	// We keep the last few hundred bytes of the previous chunk to ensure we don't split a PII match across chunk boundaries
	const overlapSize = 256
	var overlap []byte

	offset := int64(0)

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			// Combine overlap from previous chunk with current read
			// This creates "currentChunk"
			currentChunk := append(overlap, buf[:n]...)

			// Sanitize the chunk: Replace binary/garbage with spaces to help regex
			// We preserve German characters (mapped in UTF-8 or high ASCII)
			cleanChunk := sanitizeBytes(currentChunk)
			chunkStr := string(cleanChunk)

			// Update matches with offset adjustment
			// Regex offset will be relative to the start of "currentChunk"
			// Global offset = offset - len(overlap) (approximate for the start of this chunk's unique data)
			// But since we scan the *entire* currentChunk (including overlap), duplicates might occur if we don't deduplicate.
			// However, since we advance 'offset' by 'n' (new bytes read),
			// the 'baseOffset' for the start of 'currentChunk' is:
			// total_read_so_far - len(overlap) ? No.
			// Let's track absolute stream position.

			// Actually, simplest way to avoid duplicate matches in overlap region:
			// Just verify if match.Offset < (offset + n).
			// For now, let's accept potential minor dupes or filtering later.

			// Calculate base offset of this chunk in the file
			// The chunk starts at: (total bytes read so far) - (bytes just read) - (overlap from previous)
			// Wait, 'offset' tracks total bytes consumed from 'reader' *before* this Read?
			// No, let's track 'totalRead'.

			// Let's restart logic for offset tracking:
			// We just read 'n' bytes. Total read from file is 'offset + n'.
			// The content we are scanning is 'overlap' + 'buf[:n]'.
			// The 'overlap' corresponds to file offset: offset - len(overlap)

			chunkStartOffset := offset - int64(len(overlap))
			if chunkStartOffset < 0 {
				chunkStartOffset = 0
			}

			// Run all checks on this chunk
			foundMatches := runRegexChecks(chunkStr, chunkStartOffset)
			matches = append(matches, foundMatches...)

			// Prepare overlap for next iteration
			if n >= overlapSize {
				overlap = make([]byte, overlapSize)
				copy(overlap, buf[n-overlapSize:n])
			} else {
				// If read less than overlap size, assume EOF coming or small file, take it all
				overlap = make([]byte, n)
				copy(overlap, buf[:n])
			}

			offset += int64(n)
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	return matches, nil
}

// sanitizeBytes replaces non-printable characters with spaces,
// but preserves German Umlauts and common text punctuation.
func sanitizeBytes(data []byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		// Allow:
		// - Standard printable ASCII (32-126)
		// - Tab (9), Newline (10), Carriage Return (13)
		// - Extended High-ASCII (128-255) which catches UTF-8 bytes and ISO-8859-1 strings
		// This is a heuristic. It assumes anything > 127 might be text.
		// Real binary data (0x00-0x1F) is the main problem for regex / terminal output.
		if (b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13 || b > 127 {
			out[i] = b
		} else {
			out[i] = ' ' // Replace binary garbage with space
		}
	}
	return out
}

func runRegexChecks(content string, baseOffset int64) []models.Match {
	var matches []models.Match

	detectorsList := []detectors.Detector{
		detectors.NewIBANDetector(),
		detectors.NewCreditCardDetector(),
		detectors.NewEmailDetector(),
		detectors.NewPhoneDetector(),
		detectors.NewNameDetector(),
		detectors.NewIdentityKeywordDetector(),
		detectors.NewFinancialKeywordDetector(),
		detectors.NewOfficialIDKeywordDetector(),
		detectors.NewSensitiveKeywordDetector(),
	}

	for _, d := range detectorsList {
		found := d.Detect(content)
		for i := range found {
			found[i].Offset += baseOffset
			matches = append(matches, found[i])
		}
	}

	return matches
}

// Helper to get a snippet around the match
func getSnippet(fullText, match string) string {
	const contextChars = 30

	// We need to find the match in the fullText again to get indices?
	// Or we could pass indices. But 'runRegexChecks' already has 'val'.
	// Since there might be multiple identical matches, finding "first" might be wrong.
	// But for a snippet, it's roughly okay.
	// Optimization: pass start/end indices to getSnippet.

	idx := -1
	// Simple search (imperfect if duplicates exist in same chunk, but adequate for context)
	for i := 0; i < len(fullText); i++ {
		if len(fullText)-i >= len(match) && fullText[i:i+len(match)] == match {
			idx = i
			break
		}
	}

	if idx == -1 {
		return match
	}

	start := idx - contextChars
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + contextChars
	if end > len(fullText) {
		end = len(fullText)
	}

	// Clean up newlines in snippet for better log output
	clean := fullText[start:end]
	// Optional: replace newlines with spaces in snippet
	// clean = strings.ReplaceAll(clean, "\n", " ")

	return clean
}

// Helper function to create scanners based on file type
func NewScannerForFile(path string) (ContentScanner, error) {
	// Logic now handled in factory.go
	return &TextScanner{}, nil
}
