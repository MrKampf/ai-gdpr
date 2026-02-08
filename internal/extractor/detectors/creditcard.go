package detectors

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// Regex for 13-19 digit numbers, possibly separated by space or hyphen.
// This is intentionally broad to catch various formats, relying on Luhn for validation.
// Matches sequences of digits and separators, ensuring at least 13 digits total.
var creditCardPattern = regexp.MustCompile(`(4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?(\d{4}[- ]?){2,3}\d{1,4}`)

// Simpler regex to catch common formats:
// 4 blocks of 4 (Visa/Mastercard): \b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b
// Amex: \b3[47]\d{13}\b
// Let's use a composite one for Visa, MasterCard, Amex, Discover.
// Using a slightly more specific one to avoid too many false positives before Luhn.
var strictCCPattern = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b`)

// The above strict regex expects no spaces. We need to handle spaces/dashes.
// Let's go with a pattern that finds 13-19 chars of digits/separators, then strip and check.
// Look for 13-16 digits with optional separators.
var broadCCPattern = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)

type CreditCardDetector struct {
	BaseRegexDetector
}

func NewCreditCardDetector() *CreditCardDetector {
	return &CreditCardDetector{
		BaseRegexDetector: BaseRegexDetector{
			Pattern: broadCCPattern,
			Label:   models.TypeCreditCard,
		},
	}
}

func (d *CreditCardDetector) Detect(content string) []models.Match {
	candidates := d.BaseRegexDetector.Detect(content)
	var verified []models.Match

	for _, m := range candidates {
		clean := cleanCC(m.Value)

		// Check length after cleaning (13-19 digits)
		if len(clean) < 13 || len(clean) > 19 {
			continue
		}

		if luhnCheck(clean) {
			verified = append(verified, m)
		}
	}
	return verified
}

// cleanCC removes non-digit characters
func cleanCC(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// luhnCheck implements the Luhn algorithm for credit card validation
func luhnCheck(cc string) bool {
	sum := 0
	alternate := false
	for i := len(cc) - 1; i >= 0; i-- {
		n := int(cc[i] - '0')
		if alternate {
			n *= 2
			if n > 9 {
				n = (n % 10) + 1
			}
		}
		sum += n
		alternate = !alternate
	}
	return (sum % 10) == 0
}
