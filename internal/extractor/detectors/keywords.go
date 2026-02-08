package detectors

import (
	"regexp"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

// Keywords for specific categories (case-insensitive)
var (
	identityKeywords  = regexp.MustCompile(`(?i)(Name|Firstname|Lastname|Fullname|Surname|Vorname|Nachname|Familienname|Address|Street|ZIP|City|Residence|P\.O\.\s*Box|Straße|PLZ|Wohnort|Anschrift|Postfach|Email|Phone|Mobile|Fax|E-Mail|Telefon|Handy|Rufnummer|Birthdate|Place\s+of\s+birth|Gender|Age|Geburtsdatum|Geburtsort|Geschlecht|Alter)`)
	financialKeywords = regexp.MustCompile(`(?i)(Account|Sort\s+Code|Kontonummer|BLZ|Bankverbindung|Credit\s+card|Visa|Mastercard|CVV|Kreditkarte|Karteninhaber|Ablaufdatum|Tax\s+ID|Tax\s+Number|VAT\s+ID|Steuer-ID|Steuernummer|USt-IdNr)`)
	idKeywords        = regexp.MustCompile(`(?i)(Passport|Driver's\s+License|SSN|Reisepassnummer|Führerschein|Ausweis|National\s+Insurance|Health\s+Insurance|Sozialversicherung|Krankenkasse|Vers-Nr)`)
	sensitiveKeywords = regexp.MustCompile(`(?i)(Medical|Diagnosis|Patient|Therapy|Arzt|Befund|Diagnose|Krankmeldung|Religion|Political|Church|Union|Konfession|Partei|Gewerkschaft|Criminal|Offense|Court|Lawyer|Vorstrafe|Urteil|Aktenzeichen|Anwalt)`)
)

type KeywordDetector struct {
	BaseRegexDetector
}

func NewIdentityKeywordDetector() *KeywordDetector {
	return &KeywordDetector{BaseRegexDetector{Pattern: identityKeywords, Label: models.TypeIdentity}}
}

func NewFinancialKeywordDetector() *KeywordDetector {
	return &KeywordDetector{BaseRegexDetector{Pattern: financialKeywords, Label: models.TypeFinancial}}
}

func NewOfficialIDKeywordDetector() *KeywordDetector {
	return &KeywordDetector{BaseRegexDetector{Pattern: idKeywords, Label: models.TypeID}}
}

func NewSensitiveKeywordDetector() *KeywordDetector {
	return &KeywordDetector{BaseRegexDetector{Pattern: sensitiveKeywords, Label: models.TypeSensitive}}
}
