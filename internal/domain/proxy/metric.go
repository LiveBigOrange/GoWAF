package proxy

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"gowaf/internal/infra/event"
	"gowaf/internal/infra/logger"
	"gowaf/internal/domain/auxiliary/masker"
	"gowaf/internal/infra/notify"
	"gowaf/internal/infra/storage/stats"
)

type metricEvent struct {
	clientIP      string
	host          string
	path          string
	query         string
	method        string
	userAgent     string
	referer       string
	contentType   string
	rule          string
	statusCode    int
	requestID     string
	latencyMs     float64
	geoCountry    string
	geoCity       string
	geoFlag       string
	matchDetail   string
	matchLocation string
	protocol      string
	scheme        string
	requestSize   int64
	inboundBytes  int64
}

func (p *WAFProxy) metricEventWorker() {
	var buf []metricEvent
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case ev := <-p.metricEventCh:
			buf = append(buf, ev)
		batchLoop:
			for len(buf) < 100 {
				select {
				case ev := <-p.metricEventCh:
					buf = append(buf, ev)
				case <-ticker.C:
					break batchLoop
				}
			}
			for _, ev := range buf {
				p.writeMetricEvent(&ev)
			}
			buf = buf[:0]
		case <-p.metricStopCh:
			for _, ev := range buf {
				p.writeMetricEvent(&ev)
			}
			return
		}
	}
}

func (p *WAFProxy) writeMetricEvent(ev *metricEvent) {
	p.metricsManager.IncBlockedRequest()
	p.metricsManager.SaveEvent(ev.clientIP, ev.host, ev.path, ev.query, ev.method, ev.userAgent,
		ev.referer, ev.contentType, ev.rule, ev.statusCode, ev.requestID, ev.latencyMs, ev.geoCountry, ev.geoCity, ev.geoFlag, ev.matchDetail, ev.matchLocation, "block", "", ev.protocol, ev.scheme, ev.requestSize, 0, "")
	p.metricsManager.IncTopStat("blocked_ip", ev.clientIP)
	p.metricsManager.IncTopStat("attacked_path", ev.path)
	p.metricsManager.IncRuleHit(ev.rule)
	p.metricsManager.RecordMinuteStats(1, 1, ev.latencyMs, ev.inboundBytes, 0, stats.GetErrorRate(), int64(stats.GetActiveConns()))
}

func (p *WAFProxy) GetMetricDropCount() uint64 {
	return atomic.LoadUint64(&p.metricDropCount)
}

// recordBlock 记录拦截事件
func (p *WAFProxy) recordBlock(clientIP, path, method, userAgent, rule string, statusCode int, requestID, backendAddr string, start time.Time, r *http.Request, matchDetail, matchLocation string) {
	stats.IncBlocked()
	stats.IncBlockedIP(clientIP, rule)
	stats.IncBlockedPath(path, method, clientIP)
	stats.IncRuleHit(rule)

	latencyMs := time.Since(start).Seconds() * 1000
	stats.AddLatency(uint64(time.Since(start).Milliseconds()))

	var geoCountry, geoCity, geoFlag string
	if p.metricsManager != nil {
		geo := p.metricsManager.GetGeoLocation(clientIP)
		geoCountry = geo.Country
		geoCity = geo.City
		geoFlag = geo.Flag
	}

	event.AddEvent(clientIP, r.Host, masker.MaskPath(path), masker.MaskQuery(r.URL.RawQuery), method, userAgent,
		r.Header.Get("Referer"), r.Header.Get("Content-Type"), rule, statusCode, requestID, latencyMs, geoCountry, geoCity, geoFlag, masker.MaskMatchDetail(matchDetail), matchLocation, "block", "", r.Proto, getScheme(r), int64(estimateRequestSize(r)))

	if IntelCollectFn != nil {
		go IntelCollectFn("intercept_events", map[string]interface{}{
			"client_ip": clientIP, "host": r.Host, "path": path, "method": method,
			"user_agent": userAgent, "rule": rule, "status_code": statusCode,
			"request_id": requestID, "latency_ms": latencyMs,
		})
	}

	if p.metricsManager != nil {
		inboundBytes := int64(estimateRequestSize(r))
		select {
		case p.metricEventCh <- metricEvent{
			clientIP: clientIP, host: r.Host, path: masker.MaskPath(path), query: masker.MaskQuery(r.URL.RawQuery),
			method: method, userAgent: userAgent, referer: r.Header.Get("Referer"), contentType: r.Header.Get("Content-Type"),
			rule: rule, statusCode: statusCode, requestID: requestID, latencyMs: latencyMs,
			geoCountry: geoCountry, geoCity: geoCity, geoFlag: geoFlag,
			matchDetail: masker.MaskMatchDetail(matchDetail), matchLocation: matchLocation,
			protocol: r.Proto, scheme: getScheme(r), requestSize: int64(estimateRequestSize(r)), inboundBytes: inboundBytes,
		}:
		default:
			atomic.AddUint64(&p.metricDropCount, 1)
		}
	}

	log := logger.NewAccessLog().
		SetClientIP(clientIP).
		SetMethod(method).
		SetPath(masker.MaskPath(path)).
		SetStatus(statusCode).
		SetAction("block").
		SetRequestID(requestID).
		SetUpstreamAddr(backendAddr).
		SetRuleID(rule).
		SetHost(r.Host).
		SetQuery(masker.MaskQuery(r.URL.RawQuery)).
		SetUserAgent(userAgent).
		SetReferer(r.Header.Get("Referer")).
		SetContentType(r.Header.Get("Content-Type")).
		SetLatency(time.Since(start)).
		SetRequestSize(int64(estimateRequestSize(r))).
		SetProtocol(r.Proto).
		SetScheme(getScheme(r)).
		SetMatchDetail(masker.MaskMatchDetail(matchDetail)).
		SetMatchLocation(matchLocation).
		SetGeoCountry(geoCountry).
		SetGeoCity(geoCity).
		SetGeoFlag(geoFlag)

	logger.Write(*log)

	if p.notifyEngine != nil {
		p.notifyEngine.SendAlert(notify.AlertWarning, fmt.Sprintf("WAF拦截: %s", rule),
			fmt.Sprintf("客户端IP: %s\n路径: %s\n规则: %s\n详情: %s\n位置: %s\n状态: %d",
				clientIP, masker.MaskPath(path), rule, masker.MaskMatchDetail(matchDetail), matchLocation, statusCode))
	}
}
