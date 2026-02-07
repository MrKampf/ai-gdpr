package reporting

import (
	"encoding/json"
	"html/template"
	"io"
	"os"
	"sync"
	"time"

	"github.com/digimosa/ai-gdpr-scan/internal/models"
)

type Summary struct {
	TotalFilesScanned int64         `json:"total_files_scanned"`
	TotalFilesWithPII int64         `json:"total_files_with_pii"`
	TotalPIIFound     int64         `json:"total_pii_found"`
	ScanDuration      time.Duration `json:"scan_duration"`
	StartTime         time.Time     `json:"start_time"`
	EndTime           time.Time     `json:"end_time"`
}

type Report struct {
	Summary  Summary             `json:"summary"`
	Findings []models.ScanResult `json:"findings"`
	mu       sync.Mutex
}

func NewReport() *Report {
	return &Report{
		Summary: Summary{
			StartTime: time.Now(),
		},
		Findings: make([]models.ScanResult, 0),
	}
}

func (r *Report) AddResult(res models.ScanResult) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.Summary.TotalFilesScanned++
	if len(res.Findings) > 0 {
		r.Summary.TotalFilesWithPII++
		r.Summary.TotalPIIFound += int64(len(res.Findings))
		r.Findings = append(r.Findings, res)
	}
}

func (r *Report) Finalize() {
	r.Summary.EndTime = time.Now()
	r.Summary.ScanDuration = r.Summary.EndTime.Sub(r.Summary.StartTime)
}

func (r *Report) SaveJSON(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

func (r *Report) SaveHTML(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	return r.RenderHTML(file)
}

func (r *Report) RenderHTML(w io.Writer) error {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"marshal": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"mul": func(a, b float64) float64 {
			return a * b
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, r)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GDPR Scan Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                    },
                    colors: {
                        gray: {
                            800: '#1f2937',
                            900: '#111827',
                            950: '#0b0f19', // Custom deeper dark
                        },
                        primary: {
                            500: '#3b82f6', // bright blue
                            600: '#2563eb',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        /* Glassmorphism setup */
        .glass {
            background: rgba(31, 41, 55, 0.7);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }
        .card-hover:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        }
        body {
            background-color: #0b0f19;
            color: #f3f4f6;
        }
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #1f2937; 
        }
        ::-webkit-scrollbar-thumb {
            background: #4b5563; 
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #6b7280; 
        }
    </style>
</head>
<body class="antialiased min-h-screen flex flex-col font-sans selection:bg-primary-500 selection:text-white">

    <!-- Header -->
    <header class="glass sticky top-0 z-50 shadow-lg border-b border-white/5">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
            <div class="flex items-center space-x-3">
                <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-primary-600 flex items-center justify-center shadow-lg shadow-blue-500/20">
                    <svg class="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </div>
                <h1 class="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-white to-gray-400">
                    GDPR Scan Report
                </h1>
            </div>
            <div class="text-sm text-gray-400 font-medium">
                Generated: <span class="text-gray-200">{{.Summary.EndTime.Format "Jan 02, 2006 15:04:05"}}</span>
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-grow max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        
        <!-- Summary Cards -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-10">
            <!-- Total Files -->
            <div class="glass rounded-xl p-6 card-hover transition-all duration-300">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400 uppercase tracking-wider">Total Scanned</h3>
                    <div class="p-2 bg-blue-500/10 rounded-lg">
                        <svg class="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
                        </svg>
                    </div>
                </div>
                <p class="text-3xl font-bold text-white">{{.Summary.TotalFilesScanned}}</p>
                <p class="text-xs text-blue-400 mt-2">Files processed</p>
            </div>

            <!-- Issues Found -->
            <div class="glass rounded-xl p-6 card-hover transition-all duration-300 border-l-4 border-red-500">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400 uppercase tracking-wider">Files with PII</h3>
                    <div class="p-2 bg-red-500/10 rounded-lg">
                        <svg class="w-5 h-5 text-red-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                        </svg>
                    </div>
                </div>
                <p class="text-3xl font-bold text-white">{{.Summary.TotalFilesWithPII}}</p>
                <p class="text-xs text-red-400 mt-2">Requires attention</p>
            </div>

            <!-- Total PII Objects -->
            <div class="glass rounded-xl p-6 card-hover transition-all duration-300">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400 uppercase tracking-wider">Total Findings</h3>
                    <div class="p-2 bg-yellow-500/10 rounded-lg">
                        <svg class="w-5 h-5 text-yellow-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                </div>
                <p class="text-3xl font-bold text-white">{{.Summary.TotalPIIFound}}</p>
                <p class="text-xs text-yellow-400 mt-2">Individual PII matches</p>
            </div>

            <!-- Duration -->
            <div class="glass rounded-xl p-6 card-hover transition-all duration-300">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400 uppercase tracking-wider">Scan Duration</h3>
                    <div class="p-2 bg-green-500/10 rounded-lg">
                        <svg class="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                </div>
                <p class="text-3xl font-bold text-white">{{.Summary.ScanDuration}}</p>
                <p class="text-xs text-green-400 mt-2">Started {{.Summary.StartTime.Format "15:04:05"}}</p>
            </div>
        </div>

        <!-- Detailed Findings Table -->
        <div class="glass rounded-xl overflow-hidden shadow-2xl border border-white/5">
            <div class="px-6 py-5 border-b border-white/10 flex justify-between items-center bg-white/5">
                <h3 class="text-lg font-semibold text-white flex items-center gap-2">
                    <svg class="w-5 h-5 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16" />
                    </svg>
                    Detailed Findings
                </h3>
                <span class="px-3 py-1 text-xs font-medium bg-blue-500/20 text-blue-300 rounded-full border border-blue-500/20">
                    Live Data
                </span>
            </div>
            
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="bg-gray-800/50 text-gray-400 uppercase text-xs font-semibold tracking-wider">
                        <tr>
                            <th class="px-6 py-4">File Path</th>
                            <th class="px-6 py-4">Type</th>
                            <th class="px-6 py-4">Snippet</th>
                            <th class="px-6 py-4 text-center">Confidence</th>
                            <th class="px-6 py-4 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-white/5">
                        {{range .Findings}}
                            {{$filePath := .FilePath}}
                            {{range .Findings}}
                            <tr class="hover:bg-white/5 transition-colors duration-150 group">
                                <td class="px-6 py-4 font-medium text-blue-400 break-all max-w-xs">
                                    {{$filePath}}
                                </td>
                                <td class="px-6 py-4">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                        {{if eq .Type "IBAN"}} bg-purple-500/20 text-purple-300 border border-purple-500/20
                                        {{else if eq .Type "Email"}} bg-teal-500/20 text-teal-300 border border-teal-500/20
                                        {{else}} bg-gray-500/20 text-gray-300 border border-gray-500/20
                                        {{end}}">
                                        {{.Type}}
                                    </span>
                                </td>
                                <td class="px-6 py-4 text-gray-300 font-mono text-xs break-all max-w-md">
                                    {{.Snippet}}
                                </td>
                                <td class="px-6 py-4 text-center">
                                    <div class="flex items-center justify-center gap-2">
                                        <div class="w-16 bg-gray-700 rounded-full h-1.5">
                                            <div class="bg-gradient-to-r 
                                                {{if ge .Confidence 0.9}} from-green-500 to-green-400
                                                {{else if ge .Confidence 0.7}} from-yellow-500 to-yellow-400
                                                {{else}} from-red-500 to-red-400
                                                {{end}} h-1.5 rounded-full" 
                                                style="width: {{printf "%.0f" (mul .Confidence 100)}}%"></div>
                                        </div>
                                        <span class="text-xs font-medium {{if ge .Confidence 0.9}}text-green-400{{else if ge .Confidence 0.7}}text-yellow-400{{else}}text-red-400{{end}}">
                                            {{printf "%.0f" (mul .Confidence 100)}}%
                                        </span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 text-right">
                                    <div class="flex items-center justify-end gap-2">
                                        <button onclick="copyToClipboard('{{.Snippet}}')" class="text-gray-500 hover:text-white transition-colors p-1 rounded hover:bg-white/10" title="Copy Snippet">
                                            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                            </svg>
                                        </button>
                                        <button onclick="addToWhitelist('{{.Snippet}}', this)" class="text-gray-500 hover:text-green-400 transition-colors p-1 rounded hover:bg-white/10" title="Whitelist this value">
                                            <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                                            </svg>
                                        </button>
                                    </div>
                                </td>
                            </tr>
                            {{end}}
                        {{end}}
                    </tbody>
                </table>
                {{if not .Findings}}
                <div class="px-6 py-12 text-center text-gray-500">
                    <svg class="w-12 h-12 mx-auto mb-4 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <p class="text-lg font-medium">No PII Violations Found</p>
                    <p class="text-sm">Great job! Your files appear to be clean.</p>
                </div>
                {{end}}
            </div>
        </div>

        <!-- Dynamic Data Script (for advanced filtering if needed later) -->
        <script>
            const reportData = {{marshal .}};

            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(() => {
                    // Could add a toast notification here
                    console.log('Snippet copied to clipboard');
                });
            }
        </script>
    </main>

    <footer class="mt-auto py-6 border-t border-white/5 bg-gray-900/50">
        <div class="max-w-7xl mx-auto px-4 text-center text-gray-500 text-sm">
            <p>&copy; 2026 Digimosa GDPR Scanner. All rights reserved.</p>
        </div>
    </footer>
</body>
</html>
`
