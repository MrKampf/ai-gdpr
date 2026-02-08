package detectors

import (
	"regexp"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// NameRegex: Capitalized words (First Last, optionally Middle). Relaxed to len 1+ for parts like "O'Neil" or "Al" if we support apostrophes later, but let's stick to simple German/English names.
// Previous: [a-z]{2,} missed short names or names with accents if not covered. Let's make it broader.
// New: Capitalized word, space, Capitalized word. Optional middle name.
var namePattern = regexp.MustCompile(`\b[A-ZÄÖÜ][a-zäöüß]+(?:[- ]?[A-ZÄÖÜ][a-zäöüß]+){1,3}\b`)

type NameDetector struct {
	BaseRegexDetector
}

func NewNameDetector() *NameDetector {
	return &NameDetector{
		BaseRegexDetector: BaseRegexDetector{
			Pattern: namePattern,
			Label:   models.TypeName,
		},
	}
}
