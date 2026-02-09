package storage

import (
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type ScanModel struct {
	ID            uint           `gorm:"primaryKey" json:"id"`
	RootPath      string         `json:"root_path"`
	Status        string         `json:"status"` // "Running", "Completed", "Failed"
	StartTime     time.Time      `json:"start_time"`
	EndTime       time.Time      `json:"end_time"`
	Duration      time.Duration  `json:"duration"`
	TotalFiles    int64          `json:"total_files"`
	PIIFiles      int64          `json:"pii_files"`
	TotalFindings int64          `json:"total_findings"`
	Findings      []FindingModel `gorm:"foreignKey:ScanID" json:"findings"`
}

type FindingModel struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	ScanID     uint      `json:"scan_id"`
	FilePath   string    `json:"file_path"`
	Type       string    `json:"type"`
	Value      string    `json:"value"` // Sanitized snippet
	Confidence float64   `json:"confidence"`
	Reason     string    `json:"reason"`
	Feedback   string    `json:"feedback"` // "Correct" or "Incorrect"
	CreatedAt  time.Time `json:"created_at"`
}

// Global DB instance
var DB *gorm.DB

func Init(path string) error {
	var err error
	DB, err = gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return err
	}
	return DB.AutoMigrate(&ScanModel{}, &FindingModel{})
}

func CreateScan(rootPath string) (*ScanModel, error) {
	s := &ScanModel{
		RootPath:  rootPath,
		Status:    "Running",
		StartTime: time.Now(),
	}
	res := DB.Create(s)
	return s, res.Error
}

func CompleteScan(s *ScanModel, totalFiles, piiFiles, totalFindings int64) error {
	s.EndTime = time.Now()
	s.Duration = s.EndTime.Sub(s.StartTime)
	s.Status = "Completed"
	s.TotalFiles = totalFiles
	s.PIIFiles = piiFiles
	s.TotalFindings = totalFindings
	return DB.Model(s).Select("EndTime", "Duration", "Status", "TotalFiles", "PIIFiles", "TotalFindings").Updates(s).Error
}

func SaveFinding(scanID uint, path, piiType, value, reason string, confidence float64) error {
	f := FindingModel{
		ScanID:     scanID,
		FilePath:   path,
		Type:       piiType,
		Value:      value,
		Reason:     reason,
		Confidence: confidence,
		CreatedAt:  time.Now(),
	}
	// Update counts on scan atomically? Or just aggregate later.
	// For simplicity, just insert finding
	return DB.Create(&f).Error
}

func GetAllScans() ([]ScanModel, error) {
	var scans []ScanModel
	err := DB.Order("start_time desc").Find(&scans).Error
	return scans, err
}

func GetScanByID(id string) (*ScanModel, error) {
	var scan ScanModel
	err := DB.Preload("Findings").First(&scan, "id = ?", id).Error
	return &scan, err
}

func UpdateFeedback(id string, feedback string) error {
	return DB.Model(&FindingModel{}).Where("id = ?", id).Update("feedback", feedback).Error
}
