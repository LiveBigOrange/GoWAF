(function() {
    var currentRange = '15m';
    var currentMetric = 'requests';
    var splitMode = false;
    var charts = [];

    var NEEDS_SPLIT = { qps: true, cpu: true, goruntime: true, errors: true };

    function isSystemMetric(m) {
        return m === 'cpu' || m === 'goruntime';
    }

    function isMinuteRange() {
        return currentRange === '15m' || currentRange === '1h';
    }

    function shouldSplit() {
        return splitMode && NEEDS_SPLIT[currentMetric];
    }

    function destroyAll() {
        charts.forEach(function(c) { if (c) c.destroy(); });
        charts = [];
    }

    function loadTrend() {
        if (isSystemMetric(currentMetric)) {
            loadSystemTrend();
        } else {
            loadBusinessTrend();
        }
        updateSplitBtn();
    }

    function updateSplitBtn() {
        var btn = document.getElementById('splitBtn');
        if (!btn) return;
        if (NEEDS_SPLIT[currentMetric]) {
            btn.style.display = '';
            btn.textContent = splitMode ? '⊞ 合并' : '⊟ 拆分';
        } else {
            btn.style.display = 'none';
        }
    }

    function loadBusinessTrend() {
        fetch('/api/metrics/trend?range=' + currentRange)
            .then(function(r) { return r.json(); })
            .then(function(resp) {
                var raw = resp.data || {};
                var data = Array.isArray(raw) ? raw : (raw.data || []);
                data = fillBusinessGaps(data);
                renderBusinessChart(data);
                renderBusinessSummary(data);
            })
            .catch(function(e) { console.error('趋势数据加载失败:', e); });
    }

    function loadSystemTrend() {
        fetch('/api/metrics/system-trend?range=' + currentRange)
            .then(function(r) { return r.json(); })
            .then(function(resp) {
                var raw = resp.data || {};
                var data = Array.isArray(raw) ? raw : (raw.data || []);
                data = fillSystemGaps(data);
                renderSystemChart(data);
                renderSystemSummary(data);
            })
            .catch(function(e) { console.error('系统指标加载失败:', e); });
    }

    function getTimeRange() {
        var now = new Date();
        var start;
        switch (currentRange) {
            case '15m': start = new Date(now.getTime() - 15 * 60000); break;
            case '1h': start = new Date(now.getTime() - 3600000); break;
            case '12h': start = new Date(now.getTime() - 12 * 3600000); break;
            case '24h': start = new Date(now.getTime() - 24 * 3600000); break;
            case '7d': start = new Date(now.getTime() - 7 * 86400000); break;
            case '30d': start = new Date(now.getTime() - 30 * 86400000); break;
            case '90d': start = new Date(now.getTime() - 90 * 86400000); break;
            default: start = new Date(now.getTime() - 15 * 60000);
        }
        return { start: start, end: now };
    }

    function getBusinessStep() {
        switch (currentRange) {
            case '15m': case '1h': return 60000;
            default: return 3600000;
        }
    }

    function getSystemStep() {
        switch (currentRange) {
            case '15m': case '1h': return 30000;
            case '12h': case '24h': case '7d': return 300000;
            case '30d': return 3600000;
            case '90d': return 14400000;
            default: return 30000;
        }
    }

    function truncateToStep(ts, step) {
        return new Date(Math.floor(ts.getTime() / step) * step);
    }

    function formatLocalISO(d) {
        var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
        return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
            'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
    }

    function getBusinessTimeKey(d) {
        if (d.time_minute) return d.time_minute;
        if (d.time_hour) return d.time_hour;
        return '';
    }

    function fillBusinessGaps(data) {
        var step = getBusinessStep();
        var range = getTimeRange();
        var emptyRecord = function(t) {
            if (isMinuteRange()) {
                return { time_minute: formatLocalISO(t), total_requests: 0, blocked_requests: 0, avg_qps: 0, avg_latency_ms: 0, inbound_bytes: 0, outbound_bytes: 0, error_rate: 0, active_conns: 0 };
            }
            return { time_hour: formatLocalISO(t), total_requests: 0, blocked_requests: 0, avg_qps: 0, avg_latency_ms: 0, inbound_bytes: 0, outbound_bytes: 0, error_rate: 0, active_conns: 0 };
        };
        var map = {};
        data.forEach(function(d) {
            var key = getBusinessTimeKey(d);
            if (key) {
                var dt = new Date(key);
                var bucket = truncateToStep(dt, step).toISOString();
                if (!map[bucket]) map[bucket] = d;
            }
        });
        var result = [];
        var t = truncateToStep(range.start, step);
        while (t <= range.end) {
            result.push(map[t.toISOString()] || emptyRecord(t));
            t = new Date(t.getTime() + step);
        }
        return result;
    }

    function fillSystemGaps(data) {
        var step = getSystemStep();
        var range = getTimeRange();
        var emptyRecord = function(t) {
            return { time: formatLocalISO(t), cpu_usage: 0, mem_percent: 0, mem_used: 0, mem_total: 0, disk_percent: 0, disk_used: 0, disk_total: 0, goroutines: 0, num_gc: 0, gc_pause_avg: 0, heap_alloc: 0, heap_sys: 0, heap_objects: 0, stack_inuse: 0, num_thread: 0, num_fd: 0 };
        };
        var map = {};
        data.forEach(function(d) {
            if (d.time) {
                var dt = new Date(d.time);
                var bucket = truncateToStep(dt, step).toISOString();
                if (!map[bucket]) map[bucket] = d;
            }
        });
        var result = [];
        var t = truncateToStep(range.start, step);
        while (t <= range.end) {
            result.push(map[t.toISOString()] || emptyRecord(t));
            t = new Date(t.getTime() + step);
        }
        return result;
    }

    function extractTimePart(t) {
        if (!t) return '';
        var i = t.indexOf('T');
        if (i === -1) i = t.indexOf(' ');
        if (i === -1) return t;
        return t.substring(i + 1);
    }

    function extractDatePart(t) {
        if (!t) return '';
        var i = t.indexOf('T');
        if (i === -1) i = t.indexOf(' ');
        if (i === -1) return t;
        return t.substring(0, i);
    }

    function fmtLabel(d) {
        var t = getBusinessTimeKey(d);
        if (!t) return '';
        if (currentRange === '7d') return extractDatePart(t).slice(5) + ' ' + extractTimePart(t).slice(0, 5);
        if (currentRange === '30d' || currentRange === '90d') return extractDatePart(t).slice(5);
        return extractTimePart(t).slice(0, 5);
    }

    function fmtSysLabel(t) {
        if (!t) return '';
        if (currentRange === '7d') return extractDatePart(t).slice(5) + ' ' + extractTimePart(t).slice(0, 2) + ':00';
        if (currentRange === '30d' || currentRange === '90d') return extractDatePart(t).slice(5);
        return extractTimePart(t).slice(0, 5);
    }

    function makeChart(canvas, labels, datasets, scales, extra) {
        var layout = (extra && extra.layout) ? extra.layout : {};
        return new Chart(canvas, {
            type: 'line',
            data: { labels: labels, datasets: datasets },
            options: {
                responsive: true, maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: { legend: { position: 'top' } },
                layout: layout,
                scales: scales || { y: { beginAtZero: true } }
            }
        });
    }

    function ensureCanvases(count) {
        var wrap = document.getElementById('trendChartWrap');
        if (!wrap) return [];
        wrap.innerHTML = '';
        if (count > 1) {
            wrap.classList.add('trend-chart-wrap-split');
        } else {
            wrap.classList.remove('trend-chart-wrap-split');
        }
        var canvases = [];
        for (var i = 0; i < count; i++) {
            var div = document.createElement('div');
            if (count > 1) {
                div.className = 'trend-chart-split';
            } else {
                div.className = 'trend-chart-single';
            }
            var canvas = document.createElement('canvas');
            div.appendChild(canvas);
            wrap.appendChild(div);
            canvases.push(canvas);
        }
        return canvases;
    }

    function renderBusinessChart(data) {
        destroyAll();
        var labels = data.map(fmtLabel);

        if (currentMetric === 'requests') {
            var cs = ensureCanvases(1);
            charts.push(makeChart(cs[0], labels, [
                { label: '总请求', data: data.map(function(d) { return d.total_requests; }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3 },
                { label: '拦截请求', data: data.map(function(d) { return d.blocked_requests; }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3 }
            ]));
        } else if (currentMetric === 'qps') {
            if (shouldSplit()) {
                var splitLayout = { layout: { padding: { top: 4, left: 8, right: 4, bottom: 0 } } };
                var cs = ensureCanvases(2);
                charts.push(makeChart(cs[0], labels, [
                    { label: 'QPS', data: data.map(function(d) { return parseFloat(d.avg_qps).toFixed(1); }), borderColor: '#27ae60', backgroundColor: 'rgba(39,174,96,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
                charts.push(makeChart(cs[1], labels, [
                    { label: '延迟(ms)', data: data.map(function(d) { return parseFloat(d.avg_latency_ms).toFixed(1); }), borderColor: '#f39c12', backgroundColor: 'rgba(243,156,18,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
            } else {
                var cs = ensureCanvases(1);
                charts.push(makeChart(cs[0], labels, [
                    { label: 'QPS', data: data.map(function(d) { return parseFloat(d.avg_qps).toFixed(1); }), borderColor: '#27ae60', backgroundColor: 'rgba(39,174,96,0.1)', fill: true, tension: 0.3 },
                    { label: '延迟(ms)', data: data.map(function(d) { return parseFloat(d.avg_latency_ms).toFixed(1); }), borderColor: '#f39c12', backgroundColor: 'rgba(243,156,18,0.1)', fill: true, tension: 0.3, yAxisID: 'y1' }
                ], { y: { beginAtZero: true }, y1: { position: 'right', beginAtZero: true, grid: { drawOnChartArea: false } } }));
            }
        } else if (currentMetric === 'traffic') {
            var cs = ensureCanvases(1);
            charts.push(makeChart(cs[0], labels, [
                { label: '入站(KB)', data: data.map(function(d) { return (d.inbound_bytes / 1024).toFixed(1); }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3 },
                { label: '出站(KB)', data: data.map(function(d) { return (d.outbound_bytes / 1024).toFixed(1); }), borderColor: '#9b59b6', backgroundColor: 'rgba(155,89,182,0.1)', fill: true, tension: 0.3 }
            ]));
        } else if (currentMetric === 'blocks') {
            var cs = ensureCanvases(1);
            charts.push(makeChart(cs[0], labels, [
                { label: '拦截率(%)', data: data.map(function(d) { var all = d.total_requests + d.blocked_requests; return all > 0 ? (d.blocked_requests / all * 100).toFixed(2) : 0; }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3 }
            ]));
        } else if (currentMetric === 'errors') {
            if (shouldSplit()) {
                var splitLayout = { layout: { padding: { top: 4, left: 8, right: 4, bottom: 0 } } };
                var cs = ensureCanvases(2);
                charts.push(makeChart(cs[0], labels, [
                    { label: '错误率(%)', data: data.map(function(d) { return parseFloat((d.error_rate || 0)).toFixed(2); }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
                charts.push(makeChart(cs[1], labels, [
                    { label: '活跃连接', data: data.map(function(d) { return d.active_conns || 0; }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
            } else {
                var cs = ensureCanvases(1);
                charts.push(makeChart(cs[0], labels, [
                    { label: '错误率(%)', data: data.map(function(d) { return parseFloat((d.error_rate || 0)).toFixed(2); }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3 },
                    { label: '活跃连接', data: data.map(function(d) { return d.active_conns || 0; }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3, yAxisID: 'y1' }
                ], { y: { beginAtZero: true, title: { display: true, text: '%' } }, y1: { position: 'right', beginAtZero: true, grid: { drawOnChartArea: false }, title: { display: true, text: '连接数' } } }));
            }
        }
    }

    function renderSystemChart(data) {
        destroyAll();
        var labels = data.map(function(d) { return fmtSysLabel(d.time); });

        if (currentMetric === 'cpu') {
            if (shouldSplit()) {
                var splitLayout = { layout: { padding: { top: 4, left: 8, right: 4, bottom: 0 } } };
                var cs = ensureCanvases(3);
                charts.push(makeChart(cs[0], labels, [
                    { label: 'CPU (%)', data: data.map(function(d) { return parseFloat(d.cpu_usage.toFixed(1)); }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3 }
                ], { y: { beginAtZero: true, max: 100, ticks: { callback: function(v) { return v + '%'; } } } }, splitLayout));
                charts.push(makeChart(cs[1], labels, [
                    { label: '内存 (%)', data: data.map(function(d) { return parseFloat(d.mem_percent.toFixed(1)); }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3 }
                ], { y: { beginAtZero: true, max: 100, ticks: { callback: function(v) { return v + '%'; } } } }, splitLayout));
                charts.push(makeChart(cs[2], labels, [
                    { label: '磁盘 (%)', data: data.map(function(d) { return parseFloat(d.disk_percent.toFixed(1)); }), borderColor: '#f39c12', backgroundColor: 'rgba(243,156,18,0.1)', fill: true, tension: 0.3 }
                ], { y: { beginAtZero: true, max: 100, ticks: { callback: function(v) { return v + '%'; } } } }, splitLayout));
            } else {
                var cs = ensureCanvases(1);
                charts.push(makeChart(cs[0], labels, [
                    { label: 'CPU (%)', data: data.map(function(d) { return parseFloat(d.cpu_usage.toFixed(1)); }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3 },
                    { label: '内存 (%)', data: data.map(function(d) { return parseFloat(d.mem_percent.toFixed(1)); }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3 },
                    { label: '磁盘 (%)', data: data.map(function(d) { return parseFloat(d.disk_percent.toFixed(1)); }), borderColor: '#f39c12', backgroundColor: 'rgba(243,156,18,0.1)', fill: true, tension: 0.3 }
                ], { y: { beginAtZero: true, max: 100, ticks: { callback: function(v) { return v + '%'; } } } }));
            }
        } else if (currentMetric === 'goruntime') {
            if (shouldSplit()) {
                var splitLayout = { layout: { padding: { top: 4, left: 8, right: 4, bottom: 0 } } };
                var cs = ensureCanvases(5);
                charts.push(makeChart(cs[0], labels, [
                    { label: 'Goroutines', data: data.map(function(d) { return d.goroutines; }), borderColor: '#27ae60', backgroundColor: 'rgba(39,174,96,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
                charts.push(makeChart(cs[1], labels, [
                    { label: 'Heap(MB)', data: data.map(function(d) { return parseFloat((d.heap_alloc / 1024 / 1024).toFixed(1)); }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
                charts.push(makeChart(cs[2], labels, [
                    { label: 'GC暂停(ms)', data: data.map(function(d) { return parseFloat(d.gc_pause_avg.toFixed(2)); }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
                charts.push(makeChart(cs[3], labels, [
                    { label: 'HeapSys(MB)', data: data.map(function(d) { return parseFloat((d.heap_sys / 1024 / 1024).toFixed(1)); }), borderColor: '#8e44ad', backgroundColor: 'rgba(142,68,173,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
                charts.push(makeChart(cs[4], labels, [
                    { label: 'FD数', data: data.map(function(d) { return d.num_fd; }), borderColor: '#f39c12', backgroundColor: 'rgba(243,156,18,0.1)', fill: true, tension: 0.3 }
                ], null, splitLayout));
            } else {
                var cs = ensureCanvases(1);
                charts.push(makeChart(cs[0], labels, [
                    { label: 'Goroutines', data: data.map(function(d) { return d.goroutines; }), borderColor: '#27ae60', backgroundColor: 'rgba(39,174,96,0.1)', fill: true, tension: 0.3 },
                    { label: 'Heap(MB)', data: data.map(function(d) { return parseFloat((d.heap_alloc / 1024 / 1024).toFixed(1)); }), borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true, tension: 0.3, yAxisID: 'y1' },
                    { label: 'GC暂停(ms)', data: data.map(function(d) { return parseFloat(d.gc_pause_avg.toFixed(2)); }), borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true, tension: 0.3, yAxisID: 'y2' },
                    { label: 'FD数', data: data.map(function(d) { return d.num_fd; }), borderColor: '#f39c12', backgroundColor: 'rgba(243,156,18,0.1)', fill: true, tension: 0.3, yAxisID: 'y1' }
                ], {
                    y: { beginAtZero: true, position: 'left', title: { display: true, text: 'Goroutines' } },
                    y1: { beginAtZero: true, position: 'right', grid: { drawOnChartArea: false }, title: { display: true, text: 'Heap(MB) / FD' } },
                    y2: { beginAtZero: true, position: 'right', grid: { drawOnChartArea: false }, title: { display: true, text: 'GC(ms)' }, offset: true }
                }));
            }
        }
    }

    function renderBusinessSummary(data) {
        var el = document.getElementById('trendSummary');
        if (!el || !data.length) return;
        var allReq = 0, totalBlock = 0;
        var weightedLatency = 0, weightedErrRate = 0, weightedConns = 0, totalConns = 0, maxConns = 0;
        var secPerPoint = isMinuteRange() ? 60 : 3600;
        data.forEach(function(d) {
            allReq += d.total_requests + d.blocked_requests;
            totalBlock += d.blocked_requests;
            var rc = d.total_requests + d.blocked_requests;
            if (rc > 0) {
                weightedLatency += parseFloat(d.avg_latency_ms || 0) * rc;
                weightedErrRate += parseFloat(d.error_rate || 0) * rc;
                weightedConns += parseInt(d.active_conns || 0) * rc;
                totalConns += parseInt(d.active_conns || 0);
                if (d.active_conns > maxConns) maxConns = d.active_conns;
            }
        });
        var blockRate = allReq > 0 ? (totalBlock / allReq * 100).toFixed(2) : '0.00';
        var avgQPS = data.length > 0 ? (allReq / (data.length * secPerPoint)).toFixed(1) : '0.0';
        var avgLatency = allReq > 0 ? (weightedLatency / allReq).toFixed(1) : '0.0';
        var avgErrRate = allReq > 0 ? (weightedErrRate / allReq).toFixed(2) : '0.00';
        var avgConns = allReq > 0 ? Math.round(weightedConns / allReq) : 0;
        if (currentMetric === 'errors') {
            el.innerHTML =
                '<div class="trend-stat-card"><div class="trend-stat-label">平均错误率</div><div class="trend-stat-value">' + avgErrRate + '%</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">平均连接数</div><div class="trend-stat-value">' + avgConns + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">峰值连接</div><div class="trend-stat-value">' + maxConns + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">总请求</div><div class="trend-stat-value">' + allReq.toLocaleString() + '</div></div>';
        } else {
            el.innerHTML =
                '<div class="trend-stat-card"><div class="trend-stat-label">总请求</div><div class="trend-stat-value">' + allReq.toLocaleString() + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">拦截率</div><div class="trend-stat-value">' + blockRate + '%</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">平均QPS</div><div class="trend-stat-value">' + avgQPS + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">平均延迟</div><div class="trend-stat-value">' + avgLatency + 'ms</div></div>';
        }
    }

    function renderSystemSummary(data) {
        var el = document.getElementById('trendSummary');
        if (!el || !data.length) return;
        var nonZero = data.filter(function(d) { return d.cpu_usage > 0 || d.goroutines > 0; });
        if (!nonZero.length) {
            el.innerHTML = '<div class="trend-stat-card" style="grid-column: span 4"><div class="trend-stat-label">暂无数据</div><div class="trend-stat-value" style="font-size:16px;color:#95a5a6">系统指标采集已启动，请等待数据积累</div></div>';
            return;
        }
        var latest = nonZero[nonZero.length - 1];
        if (currentMetric === 'cpu') {
            var avgCPU = 0, maxCPU = 0, avgMem = 0, maxMem = 0;
            nonZero.forEach(function(d) {
                avgCPU += d.cpu_usage; avgMem += d.mem_percent;
                if (d.cpu_usage > maxCPU) maxCPU = d.cpu_usage;
                if (d.mem_percent > maxMem) maxMem = d.mem_percent;
            });
            var n = nonZero.length;
            el.innerHTML =
                '<div class="trend-stat-card"><div class="trend-stat-label">CPU</div><div class="trend-stat-value">' + latest.cpu_usage.toFixed(1) + '%</div><div class="trend-stat-sub">峰值 ' + maxCPU.toFixed(1) + '% · 均值 ' + (avgCPU / n).toFixed(1) + '%</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">内存</div><div class="trend-stat-value">' + latest.mem_percent.toFixed(1) + '%</div><div class="trend-stat-sub">' + formatBytes(latest.mem_used) + ' / ' + formatBytes(latest.mem_total) + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">磁盘</div><div class="trend-stat-value">' + latest.disk_percent.toFixed(1) + '%</div><div class="trend-stat-sub">' + formatBytes(latest.disk_used) + ' / ' + formatBytes(latest.disk_total) + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">内存峰值</div><div class="trend-stat-value">' + maxMem.toFixed(1) + '%</div></div>';
        } else if (currentMetric === 'goruntime') {
            var maxG = 0, maxH = 0;
            nonZero.forEach(function(d) { if (d.goroutines > maxG) maxG = d.goroutines; if (d.heap_alloc > maxH) maxH = d.heap_alloc; });
            el.innerHTML =
                '<div class="trend-stat-card"><div class="trend-stat-label">Goroutines</div><div class="trend-stat-value">' + latest.goroutines + '</div><div class="trend-stat-sub">峰值 ' + maxG + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">Heap</div><div class="trend-stat-value">' + formatBytes(latest.heap_alloc) + '</div><div class="trend-stat-sub">峰值 ' + formatBytes(maxH) + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">GC次数</div><div class="trend-stat-value">' + latest.num_gc + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">GC暂停</div><div class="trend-stat-value">' + latest.gc_pause_avg.toFixed(2) + 'ms</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">HeapSys</div><div class="trend-stat-value">' + formatBytes(latest.heap_sys) + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">Heap对象</div><div class="trend-stat-value">' + latest.heap_objects.toLocaleString() + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">FD数</div><div class="trend-stat-value">' + latest.num_fd + '</div></div>' +
                '<div class="trend-stat-card"><div class="trend-stat-label">OS线程</div><div class="trend-stat-value">' + latest.num_thread + '</div></div>';
        }
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0B';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        if (i < 0) i = 0;
        if (i >= units.length) i = units.length - 1;
        return (bytes / Math.pow(1024, i)).toFixed(1) + units[i];
    }

    window.setRange = function(range, btn) {
        currentRange = range;
        document.querySelectorAll('.range-btn').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        loadTrend();
    };

    window.setMetric = function(metric, btn) {
        currentMetric = metric;
        document.querySelectorAll('.trend-tab').forEach(function(b) { b.classList.remove('active'); });
        btn.classList.add('active');
        loadTrend();
    };

    var splitBtn = document.getElementById('splitBtn');
    if (splitBtn) {
        splitBtn.addEventListener('click', function() {
            splitMode = !splitMode;
            updateSplitBtn();
            loadTrend();
        });
    }

    loadTrend();
    setInterval(loadTrend, 60000);
})();
