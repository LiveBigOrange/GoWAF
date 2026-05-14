package handler

import (
	"net/http"

	"gowaf/internal/web/templates"
)

func TrendPage(w http.ResponseWriter, r *http.Request) {
	renderPage(w, r, templates.TrendTmpl, "trend", "trend")
}
