package detectors

import (
	"math/big"
	"regexp"
	"strconv"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// IBANRegex: Basic format validation (2 letters, 2 digits, 4-30 chars)
var ibanPattern = regexp.MustCompile(`[A-Z]{2}\d{2}[A-Z0-9]{4,30}`)

type IBANDetector struct {
	BaseRegexDetector
}

func NewIBANDetector() *IBANDetector {
	return &IBANDetector{
		BaseRegexDetector: BaseRegexDetector{
			Pattern: ibanPattern,
			Label:   models.TypeIBAN,
		},
	}
}

// Detect overrides the base method to include MOD-97 validation
func (d *IBANDetector) Detect(content string) []models.Match {
	// First get regex candidates
	candidates := d.BaseRegexDetector.Detect(content)

	var verified []models.Match
	for _, m := range candidates {
		// Clean spaces (though regex assumes contiguous, formats might vary in snippets)
		// But BaseRegexDetector returns exactly what matched regex.
		// Our regex `[A-Z]{2}\d{2}[A-Z0-9]{4,30}` handles contiguous blocks.
		// If IBAN has spaces (e.g. DE12 3456...), strict regex fails.
		// TODO (Future): Enhance regex to handle spaces, then clean here.
		// For now, assume scanner has stripped garbage/spaces or regex matches compact form.

		if validateIBAN(m.Value) {
			verified = append(verified, m)
		}
	}
	return verified
}

// validateIBAN performs the MOD-97 check
func validateIBAN(iban string) bool {
	if len(iban) < 15 || len(iban) > 34 {
		return false
	}

	// Move first 4 characters to the end
	rearranged := iban[4:] + iban[:4]

	var numericString string
	for _, r := range rearranged {
		if r >= '0' && r <= '9' {
			numericString += string(r)
		} else if r >= 'A' && r <= 'Z' {
			// A=10, B=11, ... Z=35
			numericString += strconv.Itoa(int(r - 'A' + 10))
		} else {
			// Invalid character
			return false
		}
	}

	// Calculate MOD 97 on the large number
	// Since the number is too big for int64, we do it in chunks
	// or use big.Int. Given constraints, let's use big.Int for simplicity/readability
	// checking import constraints? No specific constraint.

	n := new(big.Int)
	n.SetString(numericString, 10)
	rem := new(big.Int).Mod(n, big.NewInt(97))

	return rem.Int64() == 1
}
