package detectors

import (
	"regexp"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// Detector defines the interface for PII detection strategies
type Detector interface {
	Detect(content string) []models.Match
	Type() models.FindingType
}

// BaseRegexDetector implements common regex scanning logic
type BaseRegexDetector struct {
	Pattern *regexp.Regexp
	Label   models.FindingType
}

func (d *BaseRegexDetector) Detect(content string) []models.Match {
	if d.Pattern == nil {
		return nil
	}

	var found []models.Match
	matches := d.Pattern.FindAllStringIndex(content, -1)

	for _, loc := range matches {
		start, end := loc[0], loc[1]
		val := content[start:end]

		// Grab a snippet around the match
		snippetStart := start - 20
		if snippetStart < 0 {
			snippetStart = 0
		}
		snippetEnd := end + 20
		if snippetEnd > len(content) {
			snippetEnd = len(content)
		}
		snippet := content[snippetStart:snippetEnd]

		found = append(found, models.Match{
			Type:    d.Label,
			Value:   val,
			Snippet: snippet,
			Offset:  int64(start),
		})
	}
	return found
}

func (d *BaseRegexDetector) Type() models.FindingType {
	return d.Label
}
