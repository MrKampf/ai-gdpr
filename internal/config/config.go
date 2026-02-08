package config

import (
	"runtime"
)

type Config struct {
	RootPath    string
	Workers     int
	OllamaURL   string
	OllamaModel string
	Verbose     bool

	// WhitelistPath is the path to the file containing whitelisted terms
	WhitelistPath string
	DBPath        string

	// Feature Flags
	FastMode  bool // Skip files > 1MB
	DisableAI bool // Only use regex
}

func DefaultConfig() *Config {
	return &Config{
		Workers:       runtime.NumCPU() * 2, // Aggressive concurrency for I/O bound tasks
		OllamaURL:     "http://144.76.33.231:11434/api/generate",
		OllamaModel:   "llama3.2",
		WhitelistPath: "whitelist.txt",
		DBPath:        "gdpr-scan-results.db",
	}
}
