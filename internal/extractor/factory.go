package extractor

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Factory handles creation of appropriate content scanners
type Factory struct{}

// NewFactory creates a new scanner factory
func NewFactory() *Factory {
	return &Factory{}
}

// GetScannerForFile returns the appropriate ContentScanner based on file extension
func (f *Factory) GetScannerForFile(path string) (ContentScanner, string, error) {
	ext := strings.ToLower(filepath.Ext(path))

	if !f.IsSupported(ext) {
		return nil, ext, fmt.Errorf("unsupported file extension: %s", ext)
	}

	var scanner ContentScanner
	switch ext {
	case ".pdf":
		scanner = &PDFScanner{}
	case ".xlsx":
		scanner = &ExcelScanner{}
	default:
		// Default to text scanner for .txt, .csv, .log, .md, .go, etc.
		scanner = &TextScanner{}
	}

	return scanner, ext, nil
}

// IsSupported checks if the file extension is supported for scanning
func (f *Factory) IsSupported(ext string) bool {
	switch ext {
	// Block strict binaries / media
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".class", ".pyc":
		return false
	// Block strict source code (if user wants to skip logic, keep data/structure)
	// User requested to skip "where only code is in"
	case ".css", ".js", ".ts", ".go", ".c", ".cpp", ".h", ".hpp", ".java", ".py", ".rb", ".php", ".cs", ".rs", ".swift", ".kt", ".dart":
		return false
	case ".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1":
		return false
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp":
		return false
	case ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv":
		return false
	case ".zip", ".tar", ".gz", ".rar", ".7z", ".iso":
		return false
	// Allow things that might contain data: .txt, .csv, .log, .json, .xml, .yaml, .md, .pdf, .xlsx, .docx
	default:
		return true
	}
}
