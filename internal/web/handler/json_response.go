package handler

import (
	"encoding/json"
	"net/http"

	"gowaf/internal/logger"
)

func jsonSuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"data":    data,
	}); err != nil {
		logger.Error("json encode error: %v", err)
	}
}

func jsonSuccessPaged(w http.ResponseWriter, data interface{}, total int64, page int, pageSize int) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"data":      data,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	}); err != nil {
		logger.Error("json encode error: %v", err)
	}
}
