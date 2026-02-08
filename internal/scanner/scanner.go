package scanner

import (
	"context"
	"sync"

	"github.com/digimosa/ai-gdpr-scan/internal/ai"
	"github.com/digimosa/ai-gdpr-scan/internal/config"
	"github.com/digimosa/ai-gdpr-scan/internal/extractor"
	"github.com/digimosa/ai-gdpr-scan/internal/models"
	"github.com/digimosa/ai-gdpr-scan/internal/reporting"
	"github.com/digimosa/ai-gdpr-scan/internal/storage"
	"github.com/digimosa/ai-gdpr-scan/internal/whitelist"
)

// Scanner handles the orchestration of file scanning
type Scanner struct {
	cfg            *config.Config
	jobs           chan models.Job
	results        chan models.ScanResult
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	aiClient       *ai.OllamaClient
	Report         *reporting.Report
	scannerFactory *extractor.Factory
	Whitelist      *whitelist.Whitelist
	ScanModelID    uint // ID of the current scan in DB
}

func NewScanner(cfg *config.Config) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())

	wl, err := whitelist.NewWhitelist(cfg.WhitelistPath)
	if err != nil {
		// Just log warning and continue with empty whitelist if file fails
		// log.Printf("Warning: could not load whitelist: %v", err)
		// Or create empty one
		wl = &whitelist.Whitelist{}
	}

	s := &Scanner{
		cfg:            cfg,
		jobs:           make(chan models.Job, cfg.Workers*4), // Buffer relative to workers
		results:        make(chan models.ScanResult, cfg.Workers*4),
		ctx:            ctx,
		cancel:         cancel,
		done:           make(chan struct{}),
		aiClient:       ai.NewClient(cfg),
		Report:         reporting.NewReport(),
		scannerFactory: extractor.NewFactory(),
		Whitelist:      wl,
	}
	s.Report.Summary.RootPath = cfg.RootPath
	return s
}

// Start initializes the worker pool and starts the scan
func (s *Scanner) Start() {
	// Create Scan Record
	scanModel, err := storage.CreateScan(s.cfg.RootPath)
	if err == nil {
		s.ScanModelID = scanModel.ID
	} else {
		// Log error but proceed?
		// log.Printf("Failed to create scan record: %v", err)
	}

	// Start workers
	for i := 0; i < s.cfg.Workers; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}

	// Start result processor in background
	go s.processResults()

	// Start file walker
	go s.walkFiles()
}

// Wait blocks until scanning is complete
func (s *Scanner) Wait() {
	s.wg.Wait()      // Wait for all workers to finish
	close(s.results) // correct place to close results
	<-s.done         // Wait for result processor to finish
}
