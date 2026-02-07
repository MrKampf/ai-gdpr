package scanner

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

func (s *Scanner) walkFiles() {
	defer close(s.jobs)

	err := filepath.WalkDir(s.cfg.RootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			log.Printf("Error accessing path %s: %v", path, err)
			return nil // Continue walking
		}

		if !d.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if !s.scannerFactory.IsSupported(ext) {
				return nil
			}

			select {
			case <-s.ctx.Done():
				return filepath.SkipAll
			case s.jobs <- models.Job{FilePath: path}:
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("Error walking directory: %v", err)
	}
}
