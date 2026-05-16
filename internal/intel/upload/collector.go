package upload

import (
	"encoding/json"
	"strings"

	"gowaf/internal/intel/config"
	"gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
)

type Collector struct {
	store  *store.Store
	config *config.UploadConfig
	masker *MaskEngine
}

func NewCollector(store *store.Store, cfg *config.UploadConfig, masker *MaskEngine) *Collector {
	return &Collector{
		store:  store,
		config: cfg,
		masker: masker,
	}
}

func (c *Collector) Collect(eventType string, eventData map[string]interface{}) error {
	if c.config == nil || !c.config.Enabled {
		return nil
	}

	allowed := false
	for _, dt := range c.config.DataTypes {
		if dt == eventType {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil
	}

	if c.isExcluded(eventData) {
		return nil
	}

	originalJSON, err := json.Marshal(eventData)
	if err != nil {
		return err
	}

	var maskedJSON string
	var risks []string
	if c.masker != nil {
		maskedJSON, risks, _ = c.masker.MaskJSON(string(originalJSON))
	} else {
		maskedJSON = string(originalJSON)
	}

	sensitiveRisk := 0
	if len(risks) > 0 {
		sensitiveRisk = len(risks)
	}

	status := "pending"
	if c.isAutoApprove(eventData) && !c.config.AuditMode {
		status = "approved"
	}

	if c.store != nil {
		err = c.store.EnqueueUpload(&store.UploadQueueItem{
			DataType:            eventType,
			PayloadJSON:         maskedJSON,
			OriginalPayloadJSON: string(originalJSON),
			Status:              status,
			SensitiveRisk:       sensitiveRisk,
		})
		if err != nil {
			logger.Error("enqueue upload failed", "err", err)
			return err
		}
	}

	return nil
}

func (c *Collector) isExcluded(data map[string]interface{}) bool {
	if c.config.Exclusions.Enabled {
		return false
	}

	if path, ok := data["path"].(string); ok {
		for _, exclPath := range c.config.Exclusions.Paths {
			if strings.Contains(path, exclPath) {
				return true
			}
		}
	}

	if ip, ok := data["client_ip"].(string); ok {
		for _, exclIP := range c.config.Exclusions.IPs {
			if ip == exclIP {
				return true
			}
		}
	}

	if host, ok := data["host"].(string); ok {
		for _, exclHost := range c.config.Exclusions.Hosts {
			if host == exclHost {
				return true
			}
		}
	}

	return false
}

func (c *Collector) isAutoApprove(data map[string]interface{}) bool {
	if len(c.config.AutoApprovePaths) == 0 {
		return false
	}

	if path, ok := data["path"].(string); ok {
		for _, pattern := range c.config.AutoApprovePaths {
			if strings.Contains(path, pattern) {
				return true
			}
		}
	}

	return false
}
