package ai

import "github.com/digimosa/ai-gdpr-scan/internal/models"

// PromptTemplates maps each FindingType to a specific instruction for the AI.
var PromptTemplates = map[models.FindingType]string{
	models.TypeIBAN: `
		- Check if the IBAN is a real bank account number.
		- Verify if it looks like a test/example IBAN (e.g. 123456).
		- Flag it especially if it appears in a context of real transaction data.
	`,
	models.TypeEmail: `
		- Check if this is a personal email address (e.g. gmail.com, private domain).
		- Ignore generic company support emails (e.g. info@, support@, contact@).
		- Flag it if it relates to a specific individual.
	`,
	models.TypePhone: `
		- Verify if this is a valid phone number format.
		- Distinguish between personal mobile numbers and general company hotlines.
		- Flag personal mobile numbers as high risk.
	`,
	models.TypeCreditCard: `
		- Verify if this number looks like a credit card (13-19 digits).
		- Context Check: Is it near words like "CVV", "Expires", "Visa", "Mastercard"?
		- STRICTLY FLAGGING: Storing full Credit Card numbers is a critical violation.
	`,
	models.TypeName: `
		- STRICTLY IDENTIFY REAL HUMAN NAMES.
		- The regex matches capitalized words, but you must filter false positives.
		- REJECT: Company names (GmbH, Inc, Ltd), products, cities, software terms (User, Admin, ID).
		- ACCEPT: Full names like "John Smith", "Maria Garcia", "Thomas Mueller".
		- If the text is just a single word that could be a common noun, REJECT it.
		- Return the name ONLY if you are confident it refers to a specific human being.
	`,
	models.TypeIdentity: `
		- Analyze the context for identity markers (e.g. "Birthdate", "Place of Birth", "Passport").
		- Determine if this data helps identify a natural person.
	`,
	models.TypeFinancial: `
		- Analyze financial context (e.g. "Account", "Tax ID", "Salary").
		- Determine if this data relates to a person's finances.
	`,
	models.TypeSensitive: `
		- CRITICAL: Check for Article 9 GDPR special categories (Health, Religion, Political, Criminal).
		- Flag immediately if this contains medical diagnoses, political affiliation, or religious beliefs.
	`,
	models.TypeID: `
		- Check for official ID numbers (Passport, SSN, Driver's License).
		- Verify if the format resembles a valid ID number.
	`,
}

// GetDefaultPrompt returns the fallback prompt
func GetDefaultPrompt() string {
	return `Analyze the text for any Personally Identifiable Information (PII) according to GDPR.`
}
