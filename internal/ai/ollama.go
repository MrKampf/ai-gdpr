package ai

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/digimosa/ai-gdpr-scan/internal/config"
	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

type OllamaClient struct {
	BaseURL string
	Model   string
	Client  *http.Client
	Verbose bool
	LogFile string
	mu      sync.Mutex
}

type GenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
	Format string `json:"format,omitempty"`
}

type GenerateResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func NewClient(cfg *config.Config) *OllamaClient {
	return &OllamaClient{
		BaseURL: cfg.OllamaURL,
		Model:   cfg.OllamaModel,
		Client: &http.Client{
			Timeout: 30 * time.Second, // Increased timeout for slower models/network
		},
		Verbose: cfg.Verbose,
		LogFile: "ai_debug.log",
	}
}

// Ping checks if the Ollama instance is reachable and the model exists
func (c *OllamaClient) Ping() error {
	// Simple check by trying to generate a tokens response with empty prompt or just checking version
	// A better check for Ollama is GET /api/tags to see models, or just a small generation
	reqBody := GenerateRequest{
		Model:  c.Model,
		Prompt: "ping",
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	// Use a short timeout for ping
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(c.BaseURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("ollama unreachable at %s: %v", c.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	return nil
}

// ValidatePII checks if the snippet contains a valid PII of the given type
// Returns (isValid, confidence)
func (c *OllamaClient) ValidatePII(piiType, snippet string) (bool, float64, error) {
	prompt := fmt.Sprintf(
		`You are a strict data privacy validator. Check if the text below contains a valid %s. 
		
Rules:
1. For 'Name', reject:
   - Organization names (e.g. "Sozialer Wirtschaftsbetrieb")
   - Place names (e.g. "Lüneburger Heide", "Weser-Ems")
   - Department names
   - Technical terms or random words
2. Accept ONLY real human person names.
3. Answer ONLY with 'YES' or 'NO'.

Text: '%s'`,
		piiType, snippet,
	)

	reqBody := GenerateRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return false, 0, err
	}

	resp, err := c.Client.Post(c.BaseURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		// If Ollama is down, we might want to fail open (return true but low confidence) or fail closed
		// For now, return error
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, errors.New("ollama API returned non-200 status")
	}

	var genResp GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		return false, 0, err
	}

	ans := strings.TrimSpace(strings.ToUpper(genResp.Response))
	if strings.Contains(ans, "YES") {
		return true, 0.95, nil
	}

	return false, 0.1, nil
}

const promptTemplateBase = `You are a GDPR Data Privacy Officer. Analyze the following document snippet for specific Personally Identifiable Information (PII) types.
For each finding, provide a JSON object in the list.

Specific Instructions per Type found in this document:
%s

If nothing is found, return an empty list [].

Document Content:
"""
%s
"""
Return valid JSON only. Format: [{"type":"...", "value":"...", "reason":"...", "confidence": 0.0-1.0}]. No markdown.
IMPORTANT: You MUST include a "confidence" field (0.0 to 1.0) for every finding.
- 0.9-1.0: Certain (e.g. valid IBAN, explicit label "Name: John Doe")
- 0.7-0.8: Likely (e.g. "John Doe" in a list of attendees)
- 0.4-0.6: Unsure (e.g. single word "Smith", could be a company or street)
- < 0.4: False Positive (Ignore)
In the "reason" field, explain WHY you chose this confidence level. Mention context clues.`

// AnalyzeFile sends full file content (limited by token size) and customized instructions to AI
func (c *OllamaClient) AnalyzeFile(content string, types []models.FindingType) ([]FindingResult, error) {
	// Truncate content if too large (approx 4000 chars to be safe)
	if len(content) > 12000 {
		content = content[:12000] + "...(truncated)"
	}

	// Build dynamic instructions
	var instructions strings.Builder
	for _, t := range types {
		if tmpl, ok := PromptTemplates[t]; ok {
			instructions.WriteString(fmt.Sprintf("\nTarget: %s\n%s\n", t, tmpl))
		}
	}

	// Fallback if no specific types (shouldn't happen given logic)
	if instructions.Len() == 0 {
		instructions.WriteString("\nTarget: General\n" + GetDefaultPrompt())
	}

	prompt := fmt.Sprintf(promptTemplateBase, instructions.String(), content)

	responseText, err := c.callOllama(prompt, true) // pass true for JSON format
	if err != nil {
		return nil, err
	}

	return c.parseFindings(responseText)
}

func (c *OllamaClient) createPrompt(content string) string {
	return fmt.Sprintf(`You are a GDPR Data Privacy Officer. Analyze the following document snippet for ANY Personally Identifiable Information (PII) such as Names, Addresses, Emails, IBANs, or Phone Numbers.

Return the findings as a JSON list of objects. Each object must have:
- "type": The type of PII (e.g., "Name", "Email", "IBAN").
- "value": The exact PII text found.
- "reason": A brief explanation of why this constitutes a GDPR risk.

If nothing is found, return an empty list [].

Document Content:
"""
%s
"""
Return valid JSON only. Format: [{"type":"...", "value":"...", "reason":"..."}]. No markdown.`, content)
}

func (c *OllamaClient) callOllama(prompt string, jsonFormat bool) (string, error) {
	// Log Request
	c.logDebug("PROMPT", prompt)

	reqBody := GenerateRequest{
		Model:  c.Model,
		Prompt: prompt,
		Stream: false,
	}
	if jsonFormat {
		reqBody.Format = "json"
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(c.BaseURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		c.logDebug("ERROR", err.Error())
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.logDebug("ERROR", fmt.Sprintf("status %d", resp.StatusCode))
		return "", errors.New("ollama API returned non-200 status")
	}

	var genResp GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		c.logDebug("ERROR", err.Error())
		return "", err
	}

	// Log Response
	c.logDebug("RESPONSE", genResp.Response)

	return strings.TrimSpace(genResp.Response), nil
}

func (c *OllamaClient) logDebug(kind, message string) {
	// Console Log (Always print to stdout for now as requested by user)
	// if c.Verbose {
	if len(message) > 500 {
		log.Printf("[AI-%s] %s... (truncated)", kind, message[:500])
	} else {
		log.Printf("[AI-%s] %s", kind, message)
	}
	// }

	// File Log (Always, or concurrent safe)
	c.mu.Lock()
	defer c.mu.Unlock()

	f, err := os.OpenFile(c.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	timestamp := time.Now().Format(time.RFC3339)
	entry := fmt.Sprintf("[%s] [%s]\n%s\n--------------------------------------------------\n", timestamp, kind, message)
	if _, err := f.WriteString(entry); err != nil {
		// ignore write error
	}
}

func (c *OllamaClient) parseFindings(responseText string) ([]FindingResult, error) {
	// Clean up markdown code blocks
	cleanText := cleanMarkdown(responseText)

	start := strings.Index(cleanText, "[")
	end := strings.LastIndex(cleanText, "]")

	if start == -1 || end == -1 {
		return []FindingResult{{
			Type:   "Unknown",
			Value:  responseText, // Return raw text for debugging
			Reason: "AI returned non-JSON response",
		}}, nil
	}

	jsonPart := cleanText[start : end+1]

	// localized struct for unmarshalling
	type AiFinding struct {
		Type       string  `json:"type"`
		Value      string  `json:"value"`
		Reason     string  `json:"reason"`
		Confidence float64 `json:"confidence"`
	}

	var findings []AiFinding
	if err := json.Unmarshal([]byte(jsonPart), &findings); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %v", err)
	}

	var results []FindingResult
	for _, f := range findings {
		// Default confidence if missing or 0
		conf := f.Confidence
		if conf == 0 {
			conf = 0.8 // Default to high if AI didn't specify
		}

		results = append(results, FindingResult{
			Type:       f.Type,
			Value:      f.Value,
			Reason:     f.Reason,
			Confidence: conf,
		})
	}
	return results, nil
}

func cleanMarkdown(text string) string {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "```json") {
		text = strings.TrimPrefix(text, "```json")
	} else if strings.HasPrefix(text, "```") {
		text = strings.TrimPrefix(text, "```")
	}
	text = strings.TrimSuffix(text, "```")
	return strings.TrimSpace(text)
}

type FindingResult struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
}
