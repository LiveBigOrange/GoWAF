package handler

import (
	"net/http"
	"time"

	"gowaf/internal/web/templates"
)

func CompliancePage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.ComplianceTmpl, "compliance", "compliance")
}

func APIComplianceReport(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ComplianceGenerator, "合规性检查器") {
		return
	}
	endStr := r.URL.Query().Get("end")
	startStr := r.URL.Query().Get("start")

	end := time.Now()
	start := end.AddDate(0, -1, 0)

	if endStr != "" {
		if t, err := time.Parse("2006-01-02", endStr); err == nil {
			end = t
		}
	}
	if startStr != "" {
		if t, err := time.Parse("2006-01-02", startStr); err == nil {
			start = t
		}
	}

	report, err := deps.ComplianceGenerator.Generate(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	jsonSuccess(w, report)
}

func APIComplianceHTML(w http.ResponseWriter, r *http.Request) {
	if !requireManager(w, deps.ComplianceGenerator, "合规性检查器") {
		return
	}
	endStr := r.URL.Query().Get("end")
	startStr := r.URL.Query().Get("start")

	end := time.Now()
	start := end.AddDate(0, -1, 0)

	if endStr != "" {
		if t, err := time.Parse("2006-01-02", endStr); err == nil {
			end = t
		}
	}
	if startStr != "" {
		if t, err := time.Parse("2006-01-02", startStr); err == nil {
			start = t
		}
	}

	report, err := deps.ComplianceGenerator.Generate(start, end)
	if err != nil {
		jsonError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(deps.ComplianceGenerator.GenerateHTML(report)))
}
