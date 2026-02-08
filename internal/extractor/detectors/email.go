package detectors

import (
	"regexp"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// EmailRegex: Standard email pattern
var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

type EmailDetector struct {
	BaseRegexDetector
}

func NewEmailDetector() *EmailDetector {
	return &EmailDetector{
		BaseRegexDetector: BaseRegexDetector{
			Pattern: emailPattern,
			Label:   models.TypeEmail,
		},
	}
}
