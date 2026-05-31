package rules

import (
	"time"

	"gowaf/internal/infra/logger"
)

var maliciousUAKeywords = []string{
	"nikto", "nmap", "sqlmap", "dirbuster", "gobuster",
	"wpscan", "masscan", "zap", "burp", "hydra",
	"wfuzz", "ffuf", "dirb",
}

// MigrateUABlacklistToBot 将UA黑名单中恶意工具相关规则标记为migrated
// 标记后这些规则不再参与CheckUA匹配，由Bot模块统一处理
func (e *Engine) MigrateUABlacklistToBot() {
	migratedCount := 0
	for _, keyword := range maliciousUAKeywords {
		rows, err := e.db.Query(
			"SELECT id, pattern FROM ua_rules WHERE rule_type='blacklist' AND enabled=1 AND COALESCE(source,'local') != 'migrated' AND pattern LIKE ?",
			"%"+keyword+"%")
		if err != nil {
			logger.Warn("UA迁移查询失败", "keyword", keyword, "err", err)
			continue
		}
		var ids []int
		for rows.Next() {
			var id int
			var pattern string
			if rows.Scan(&id, &pattern) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()

		for _, id := range ids {
			now := time.Now().Format("2006-01-02 15:04:05")
			_, err := e.db.Exec(
				"UPDATE ua_rules SET source='migrated', enabled=0, migrated_at=? WHERE id=?",
				now, id)
			if err != nil {
				logger.Warn("UA规则迁移标记失败", "id", id, "err", err)
				continue
			}
			migratedCount++
		}
	}

	if migratedCount > 0 {
		logger.Info("UA恶意工具规则迁移到Bot模块完成", "migrated_count", migratedCount)
		e.loadAllRules()
	}
}
