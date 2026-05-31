package asyncextract

import (
	"database/sql"
	"sync"
	"sync/atomic"
	"time"

	"gowaf/internal/domain/security/detector"
	"gowaf/internal/infra/logger"
)

const maxBodySize = 4096

type ExtractRequest struct {
	RequestID  string
	ClientIP   string
	Method     string
	Path       string
	Query      string
	Body       string
	UserAgent  string
	SourceRule string
	Timestamp  time.Time
}

type ExtractResult struct {
	RequestID      string
	AttackType     string
	FeatureDetail  string
	SourceRule     string
	ClientIP       string
	Path           string
	ExtractionMode string
	CreatedAt      time.Time
}

type AsyncFeatureExtractor struct {
	ch          chan ExtractRequest
	detectorMgr *detector.Manager
	logdb       *sql.DB
	workerCount int
	stopCh      chan struct{}
	wg          sync.WaitGroup
	dropCount   atomic.Int64
	enabled     atomic.Int32
}

func NewAsyncFeatureExtractor(detectorMgr *detector.Manager, logdb *sql.DB, workerCount, channelSize int) *AsyncFeatureExtractor {
	if workerCount <= 0 {
		workerCount = 4
	}
	if channelSize <= 0 {
		channelSize = 1024
	}
	return &AsyncFeatureExtractor{
		ch:          make(chan ExtractRequest, channelSize),
		detectorMgr: detectorMgr,
		logdb:       logdb,
		workerCount: workerCount,
		stopCh:      make(chan struct{}),
	}
}

func (e *AsyncFeatureExtractor) Start() {
	e.enabled.Store(1)
	if e.logdb != nil {
		e.ensureTables()
	}
	for i := 0; i < e.workerCount; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}
	logger.Info("异步攻击特征提取器启动", "workers", e.workerCount, "channel_size", cap(e.ch))
}

func (e *AsyncFeatureExtractor) Stop() {
	e.enabled.Store(0)
	close(e.stopCh)
	e.wg.Wait()
	logger.Info("异步攻击特征提取器停止", "dropped", e.dropCount.Load())
}

// Submit 非阻塞提交提取请求，channel满时返回false
func (e *AsyncFeatureExtractor) Submit(req ExtractRequest) bool {
	if e.enabled.Load() == 0 {
		return false
	}
	select {
	case e.ch <- req:
		return true
	default:
		e.dropCount.Add(1)
		return false
	}
}

func (e *AsyncFeatureExtractor) DropCount() int64 {
	return e.dropCount.Load()
}

func (e *AsyncFeatureExtractor) worker(id int) {
	defer e.wg.Done()
	for {
		select {
		case <-e.stopCh:
			return
		case req := <-e.ch:
			e.processRequest(req)
		}
	}
}

func (e *AsyncFeatureExtractor) processRequest(req ExtractRequest) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warn("异步特征提取worker panic", "err", r)
		}
	}()

	if e.detectorMgr == nil {
		return
	}

	body := req.Body
	if len(body) > maxBodySize {
		body = body[:maxBodySize]
	}

	var results []ExtractResult

	pathDet, _, _, _, pathDesc := e.detectorMgr.CheckPathTraversal(req.Path, req.Query, body)
	if pathDet {
		results = append(results, ExtractResult{
			RequestID:      req.RequestID,
			AttackType:     "path_traversal",
			FeatureDetail:  pathDesc,
			SourceRule:     req.SourceRule,
			ClientIP:       req.ClientIP,
			Path:           req.Path,
			ExtractionMode: "async_extracted",
			CreatedAt:      time.Now(),
		})
	}

	sqlDet, _, _, _, sqlDesc := e.detectorMgr.CheckSQLInjection(req.Path, req.Query, body)
	if sqlDet {
		results = append(results, ExtractResult{
			RequestID:      req.RequestID,
			AttackType:     "sql_injection",
			FeatureDetail:  sqlDesc,
			SourceRule:     req.SourceRule,
			ClientIP:       req.ClientIP,
			Path:           req.Path,
			ExtractionMode: "async_extracted",
			CreatedAt:      time.Now(),
		})
	}

	for _, result := range results {
		e.persistResult(result)
	}
}

func (e *AsyncFeatureExtractor) persistResult(result ExtractResult) {
	if e.logdb == nil {
		return
	}
	_, err := e.logdb.Exec(`INSERT INTO attack_feature_log
		(request_id, attack_type, feature_detail, source_rule, extraction_mode, client_ip, path, created_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
		result.RequestID, result.AttackType, result.FeatureDetail, result.SourceRule,
		result.ExtractionMode, result.ClientIP, result.Path, result.CreatedAt.Format(time.RFC3339))
	if err != nil {
		logger.Warn("异步特征提取持久化失败", "err", err)
	}
}

func (e *AsyncFeatureExtractor) ensureTables() {
	_, err := e.logdb.Exec(`CREATE TABLE IF NOT EXISTS attack_feature_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		request_id TEXT NOT NULL,
		attack_type TEXT NOT NULL,
		feature_detail TEXT NOT NULL,
		source_rule TEXT NOT NULL,
		extraction_mode TEXT NOT NULL DEFAULT 'async_extracted',
		client_ip TEXT,
		path TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		logger.Warn("attack_feature_log表创建失败", "err", err)
		return
	}
	e.logdb.Exec(`CREATE INDEX IF NOT EXISTS idx_feature_log_request ON attack_feature_log(request_id)`)
	e.logdb.Exec(`CREATE INDEX IF NOT EXISTS idx_feature_log_time ON attack_feature_log(created_at)`)
}
