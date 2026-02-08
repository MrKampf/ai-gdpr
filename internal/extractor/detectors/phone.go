package detectors

import (
	"regexp"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// PhoneRegex: International (+49) or local (0176) formats
var phonePattern = regexp.MustCompile(`(\+|00)[0-9][0-9 \-\./]{6,}`)

type PhoneDetector struct {
	BaseRegexDetector
}

func NewPhoneDetector() *PhoneDetector {
	return &PhoneDetector{
		BaseRegexDetector: BaseRegexDetector{
			Pattern: phonePattern,
			Label:   models.TypePhone,
		},
	}
}
