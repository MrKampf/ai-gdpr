package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/digimosa/ai-gdpr-scan/internal/ai"
	"github.com/digimosa/ai-gdpr-scan/internal/config"
	"github.com/digimosa/ai-gdpr-scan/internal/scanner"
	"github.com/digimosa/ai-gdpr-scan/internal/server"
	"github.com/digimosa/ai-gdpr-scan/internal/storage"
)

func main() {
	// Parse CLI flags
	rootPath := flag.String("path", ".", "Root directory to scan")
	scan := flag.Bool("scan", false, "Execute scan immediately (CLI mode)")
	workers := flag.Int("workers", 0, "Number of concurrent workers (default: auto)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	serve := flag.Bool("serve", false, "Start a web server to review results and manage whitelist after scan")
	port := flag.String("port", "8080", "Port for the web server")
	flag.Parse()

	// Setup configuration
	cfg := config.DefaultConfig()
	cfg.RootPath = *rootPath
	cfg.Verbose = *verbose
	if *workers > 0 {
		cfg.Workers = *workers
	}

	// Initialize Storage
	fmt.Printf("Initializing database at: %s\n", cfg.DBPath)
	if err := storage.Init(cfg.DBPath); err != nil {
		fmt.Printf("[ERROR] Failed to initialize database: %v\n", err)
		return
	}

	fmt.Printf("Starting GDPR Scan on: %s\n", cfg.RootPath)
	fmt.Printf("Workers: %d\n", cfg.Workers)
	fmt.Printf("Ollama Model: %s\n", cfg.OllamaModel)

	// Check Ollama connection
	fmt.Print("Checking Ollama connection... ")
	aiClient := ai.NewClient(cfg)
	if err := aiClient.Ping(); err != nil {
		fmt.Printf("FAILED\n[ERROR] Could not connect to Ollama: %v\n", err)
		fmt.Println("Please ensure Ollama is running and accessible.")
		// We might want to exit here or continue with warning
		// Given the requirements, let's exit to prevent false confidence
		// os.Exit(1)
		// BUT user might want to scan anyway without AI.
		// For now, let's warn heavily and continue but maybe update config to disable AI?
		// Let's exit as requested "test check" implies a gate.
		return
	}
	fmt.Println("OK")

	// Initialize scanner
	s := scanner.NewScanner(cfg)

	// CLI Mode: Scan immediately if requested
	if *scan {
		start := time.Now()

		// The Start method runs the walker and workers in background
		s.Start()
		s.Wait()

		fmt.Printf("\nScan complete in %s\n", time.Since(start))

		// Save Reports
		jsonFile := "scan_report.json"
		if err := s.Report.SaveJSON(jsonFile); err != nil {
			fmt.Printf("Error saving JSON report: %v\n", err)
		} else {
			fmt.Printf("JSON report saved to: %s\n", jsonFile)
		}

		htmlFile := "scan_report.html"
		if err := s.Report.SaveHTML(htmlFile); err != nil {
			fmt.Printf("Error saving HTML report: %v\n", err)
		} else {
			fmt.Printf("HTML report saved to: %s\n", htmlFile)
		}
	}

	// Server Mode: Start web UI
	if *serve {
		srv := server.NewServer(cfg, s.Report, s.Whitelist)
		addr := fmt.Sprintf("0.0.0.0:%s", *port)
		fmt.Printf("\n[SERVER] Starting review server at http://localhost:%s\n", *port)
		fmt.Println("Press Ctrl+C to stop")
		if err := srv.Start(addr); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	} else if !*scan {
		// No action specified
		fmt.Println("No action specified.")
		fmt.Println("Use -scan to run a CLI scan immediately.")
		fmt.Println("Use -serve to start the web dashboard.")
		flag.PrintDefaults()
	}
}
