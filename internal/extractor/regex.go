package extractor

import (
	"regexp"
)

// Regex patterns for PII
var (
	// Basic regex for IBAN validation (not full modulo check, just format)
	// Matches 2 letters, 2 digits, then 4-30 chars of letters/digits
	IBANRegex = regexp.MustCompile(`[A-Z]{2}\d{2}[A-Z0-9]{4,30}`)

	// Simple email regex for speed
	EmailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

	// Phone regex: Matches international (+49) or local (0176) formats
	// Requires at least 7 digits to avoid false positives like years
	// Updated to handle spaces/formatting better
	PhoneRegex = regexp.MustCompile(`(\+|00)[0-9][0-9 \-\./]{6,}`)

	// Name regex: Heuristic to find capitalized words that might be names
	// Updated to support German Umlauts (ÄÖÜäöüß)
	// Matches: "Firstname Lastname" where both start with uppercase
	NameRegex = regexp.MustCompile(`\b[A-ZÄÖÜ][a-zäöüß]{2,}\s+[A-ZÄÖÜ][a-zäöüß]{2,}\b`)

	// --- Enhanced Keyword Detection ---
	// Note: We use string literals for keywords to avoid complex regex logic for now,
	// but wrapped in (?i) for case insensitivity.

	// Identity & Contact Keywords
	IdentityKeywords = regexp.MustCompile(`(?i)(Name|Firstname|Lastname|Fullname|Surname|Vorname|Nachname|Familienname|Address|Street|ZIP|City|Residence|P\.O\.\s*Box|Straße|PLZ|Wohnort|Anschrift|Postfach|Email|Phone|Mobile|Fax|E-Mail|Telefon|Handy|Rufnummer|Birthdate|Place\s+of\s+birth|Gender|Age|Geburtsdatum|Geburtsort|Geschlecht|Alter)`)

	// Financial Data Keywords
	FinancialKeywords = regexp.MustCompile(`(?i)(Account|Sort\s+Code|Kontonummer|BLZ|Bankverbindung|Credit\s+card|Visa|Mastercard|CVV|Kreditkarte|Karteninhaber|Ablaufdatum|Tax\s+ID|Tax\s+Number|VAT\s+ID|Steuer-ID|Steuernummer|USt-IdNr)`)

	// ID & Official Keywords
	IDKeywords = regexp.MustCompile(`(?i)(Passport|Driver's\s+License|SSN|Reisepassnummer|Führerschein|Ausweis|National\s+Insurance|Health\s+Insurance|Sozialversicherung|Krankenkasse|Vers-Nr)`)

	// Special Categories (sensitive)
	SensitiveKeywords = regexp.MustCompile(`(?i)(Medical|Diagnosis|Patient|Therapy|Arzt|Befund|Diagnose|Krankmeldung|Religion|Political|Church|Union|Konfession|Partei|Gewerkschaft|Criminal|Offense|Court|Lawyer|Vorstrafe|Urteil|Aktenzeichen|Anwalt)`)
)

type FindingType string

const (
	TypeIBAN      FindingType = "IBAN"
	TypeEmail     FindingType = "Email"
	TypePhone     FindingType = "Phone"
	TypeName      FindingType = "Name"
	TypeIdentity  FindingType = "Identity"
	TypeFinancial FindingType = "Financial"
	TypeID        FindingType = "OfficialID"
	TypeSensitive FindingType = "Sensitive"
)

type Match struct {
	Type    FindingType
	Snippet string
	Value   string
	Offset  int64
}
