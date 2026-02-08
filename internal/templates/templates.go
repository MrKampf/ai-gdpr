package templates

import (
	_ "embed"
)

//go:embed report.html
var ReportHTML string

//go:embed dashboard.html
var DashboardHTML string

//go:embed loading.html
var LoadingHTML string
