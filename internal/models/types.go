package models

import "time"

// Finding represents a single PII match found in a file
type Finding struct {
	Type       string  `json:"type"`              // e.g., "IBAN", "Email", "Phone"
	Snippet    string  `json:"snippet"`           // Redacted or partial snippet for verification
	Confidence float64 `json:"confidence"`        // 0.0 to 1.0
	Offset     int64   `json:"offset"`            // Byte offset in file
	Context    string  `json:"context,omitempty"` // AI explanation or surrounding context
}

// ScanResult represents the outcome of scanning a single file
type ScanResult struct {
	FilePath  string    `json:"file_path"`
	FileType  string    `json:"file_type"`
	Size      int64     `json:"size"`
	Findings  []Finding `json:"findings"`
	Error     error     `json:"-"` // Internal error tracking
	ErrorMsg  string    `json:"error,omitempty"`
	ScanTime  time.Duration
	Timestamp time.Time
}

// Job represents a file to be scanned by a worker
type Job struct {
	FilePath string
}

type FindingType string

const (
	TypeIBAN       FindingType = "IBAN"
	TypeEmail      FindingType = "Email"
	TypePhone      FindingType = "Phone"
	TypeName       FindingType = "Name"
	TypeIdentity   FindingType = "Identity"
	TypeFinancial  FindingType = "Financial"
	TypeID         FindingType = "OfficialID"
	TypeSensitive  FindingType = "Sensitive"
	TypeCreditCard FindingType = "CreditCard"
)

type Match struct {
	Type    FindingType
	Snippet string
	Value   string
	Offset  int64
}
