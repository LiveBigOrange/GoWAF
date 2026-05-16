(function() {
    var requestFailCount = 0;
    var maxFailCount = 5;
    var requestStopped = false;
    var intervals = [];
    var trendChart = null;
    var currentRange = 'realtime';
    var currentTab = 'requests';
    var autoRefreshInterval = null;
    var startTime = null;
    var uptimeInterval = null;

    window._dashboard = {
        intervals: intervals,
        getRequestStopped: function() { return requestStopped; },
        setRequestStopped: function(v) { requestStopped = v; },
        getRequestFailCount: function() { return requestFailCount; },
        setRequestFailCount: function(v) { requestFailCount = v; },
        getAutoRefreshInterval: function() { return autoRefreshInterval; },
        setAutoRefreshInterval: function(v) { autoRefreshInterval = v; },
        getStartTime: function() { return startTime; },
        setStartTime: function(v) { startTime = v; },
        getUptimeInterval: function() { return uptimeInterval; },
        setUptimeInterval: function(v) { uptimeInterval = v; }
    };

    function formatTimeAgo(timeStr) {
        if (!timeStr) return '';
        try {
            var time = new Date(timeStr);
            if (time.getFullYear() < 2000) return '';
            var now = new Date();
            var diff = Math.floor((now - time) / 1000);
            if (diff < 0 || diff > 365 * 24 * 3600) return '';
            if (diff === 0) return '刚刚';
            if (diff < 60) return diff + '秒前';
            if (diff < 3600) return Math.floor(diff / 60) + '分钟前';
            if (diff < 86400) return Math.floor(diff / 3600) + '小时前';
            return Math.floor(diff / 86400) + '天前';
        } catch(e) {
            return '';
        }
    }

    function fetchWithErrorCount(url, options) {
        if (requestStopped) return Promise.reject(new Error('请求已停止'));
        return fetch(url, options)
            .then(function(response) {
                if (!response.ok) throw new Error('HTTP error ' + response.status);
                requestFailCount = 0;
                return response;
            })
            .catch(function(error) {
                requestFailCount++;
                if (requestFailCount >= maxFailCount && !requestStopped) {
                    requestStopped = true;
                    console.error('连续失败 ' + maxFailCount + ' 次，已停止自动刷新');
                    intervals.forEach(function(id) { clearInterval(id); });
                    intervals = [];
                    showConnectionLostMessage();
                }
                throw error;
            });
    }

    function showConnectionLostMessage() {
        var alertDiv = document.createElement('div');
        alertDiv.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);background:#e74c3c;color:white;padding:12px 24px;border-radius:8px;z-index:9999;box-shadow:0 4px 12px rgba(0,0,0,0.15);cursor:pointer;';
        alertDiv.innerHTML = '⚠️ 与服务器连接中断，请刷新页面重试 <span style="margin-left:12px;opacity:0.7;">✕</span>';
        alertDiv.onclick = function() { document.body.removeChild(alertDiv); };
        document.body.appendChild(alertDiv);
    }

    function fetchConfig() {
        fetchWithErrorCount('/api/proxy/list').then(function(r) { return r.json(); }).then(function(resp) {
            var d = resp.data || [];
            if (d.length > 0) {
                var enabledProxies = d.filter(function(p) { return p.enabled; });
                if (enabledProxies.length > 0) {
                    document.getElementById('proxyPorts').innerText = enabledProxies.map(function(p) { return p.listen_addr + '(' + p.protocol.toUpperCase() + ')'; }).join(', ');
                } else {
                    document.getElementById('proxyPorts').innerText = '未启用';
                }
            } else {
                document.getElementById('proxyPorts').innerText = '未配置';
            }
        }).catch(function() {});

        fetchWithErrorCount('/api/domain/list').then(function(r) { return r.json(); }).then(function(resp) {
            var d = resp.data || [];
            if (d.length > 0) {
                var enabledDomains = d.filter(function(dom) { return dom.enabled; });
                document.getElementById('domainCount').innerText = enabledDomains.length + ' 个域名';
            } else {
                document.getElementById('domainCount').innerText = '未配置';
            }
        }).catch(function() {});

        fetchWithErrorCount('/api/cert/list').then(function(r) { return r.json(); }).then(function(resp) {
            var d = resp.data || [];
            if (d.length > 0) {
                document.getElementById('certCount').innerText = d.length + ' 个证书';
            } else {
                document.getElementById('certCount').innerText = '未配置';
            }
        }).catch(function() {});

        fetchWithErrorCount('/api/config').then(function(r) { return r.json(); }).then(function(resp) {
            var d = resp.data || {};
            document.getElementById('adminAddr').innerText = d.admin_addr || '未配置';
            var rateLimitEl = document.getElementById('rateLimitStatus');
            if (d.rate_limit_enabled) {
                rateLimitEl.textContent = '✅ 已开启';
                rateLimitEl.style.color = '#27ae60';
            } else {
                rateLimitEl.textContent = '❌ 已关闭';
                rateLimitEl.style.color = '#e74c3c';
            }
        }).catch(function() {});

        fetchWithErrorCount('/api/backend/list').then(function(r) { return r.json(); }).then(function(resp) {
            var d = resp.data || [];
            if (d.length > 0) {
                var healthyCount = d.filter(function(b) { return b.healthy; }).length;
                document.getElementById('backendAddr').innerText = healthyCount + '/' + d.length + ' 健康';
            } else {
                document.getElementById('backendAddr').innerText = '未配置';
            }
        }).catch(function() {});
    }

    function updateUptime() {
        if (!startTime) return;
        var elapsed = Math.floor((Date.now() - startTime) / 1000);
        var hours = Math.floor(elapsed / 3600);
        var mins = Math.floor((elapsed % 3600) / 60);
        var secs = elapsed % 60;
        var uptimeEl = document.getElementById('uptime');
        if (uptimeEl) {
            uptimeEl.innerText = hours + 'h ' + mins + 'm ' + secs + 's';
        }
    }

    var DETECTOR_ICONS = {
        sql_injection: '💉', xss: '🎯', command_injection: '⚙️', ssrf: '🌐',
        path_traversal: '📂', header_injection: '📋', sensitive_data: '🔒',
        file_upload: '📎', error_leak: '⚠️', request_smuggling: '🔄',
        xxe: '📄', nosql: '🗃️', ssti: '🧩'
    };

    var DETECTOR_LABELS = {
        sql_injection: 'SQL注入', xss: 'XSS', command_injection: '命令注入', ssrf: 'SSRF',
        path_traversal: '路径遍历', header_injection: '头部注入', sensitive_data: '敏感数据',
        file_upload: '文件上传', error_leak: '错误泄露', request_smuggling: '请求走私',
        xxe: 'XXE', nosql: 'NoSQL', ssti: 'SSTI'
    };

    function fetchDetectorStatus() {
        fetchWithErrorCount('/api/detector/list').then(function(r) { return r.json(); }).then(function(resp) {
            var data = resp.data || [];
            if (!data || data.length === 0) return;
            var row = document.getElementById('detectorStatusRow');
            if (!row) return;
            var html = '';
            data.forEach(function(detector) {
                var label = DETECTOR_LABELS[detector.detector_type] || detector.detector_type;
                var statusText, statusColor;
                if (detector.enabled && detector.observation_mode) {
                    statusText = '🔵 观察';
                    statusColor = '#2980b9';
                } else if (detector.enabled) {
                    statusText = '✅ 启用';
                    statusColor = '#27ae60';
                } else {
                    statusText = '❌ 禁用';
                    statusColor = '#e74c3c';
                }
                html += '<div style="text-align:center;"><span style="color:#7f8c8d;font-size:12px;">' + label + '</span><br><strong style="font-size:12px;color:' + statusColor + ';">' + statusText + '</strong></div>';
            });
            row.innerHTML = html;
        }).catch(function() {});
    }

    function initCharts() {
        var ctx = document.getElementById('trendChart').getContext('2d');
        trendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    { label: '总请求', data: [], borderColor: '#409eff', backgroundColor: 'rgba(64, 158, 255, 0.1)', fill: true, tension: 0.4, pointRadius: 2 },
                    { label: '拦截', data: [], borderColor: '#e74c3c', backgroundColor: 'rgba(231, 76, 60, 0.1)', fill: true, tension: 0.4, pointRadius: 2 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'top' } },
                scales: { x: { grid: { display: false } }, y: { beginAtZero: true, suggestedMax: 1 } }
            }
        });
    }

    function updateChartConfig(tab) {
        if (!trendChart) return;
        switch(tab) {
            case 'requests':
                trendChart.data.datasets[0].label = '总请求'; trendChart.data.datasets[0].borderColor = '#409eff'; trendChart.data.datasets[0].backgroundColor = 'rgba(64, 158, 255, 0.1)';
                trendChart.data.datasets[1].label = '拦截'; trendChart.data.datasets[1].borderColor = '#e74c3c'; trendChart.data.datasets[1].backgroundColor = 'rgba(231, 76, 60, 0.1)';
                break;
            case 'qps':
                trendChart.data.datasets[0].label = 'QPS'; trendChart.data.datasets[0].borderColor = '#27ae60'; trendChart.data.datasets[0].backgroundColor = 'rgba(39, 174, 96, 0.1)';
                trendChart.data.datasets[1].label = '延迟(ms)'; trendChart.data.datasets[1].borderColor = '#f39c12'; trendChart.data.datasets[1].backgroundColor = 'rgba(243, 156, 18, 0.1)';
                break;
            case 'traffic':
                trendChart.data.datasets[0].label = '入站(KB)'; trendChart.data.datasets[0].borderColor = '#9b59b6'; trendChart.data.datasets[0].backgroundColor = 'rgba(155, 89, 182, 0.1)';
                trendChart.data.datasets[1].label = '出站(KB)'; trendChart.data.datasets[1].borderColor = '#1abc9c'; trendChart.data.datasets[1].backgroundColor = 'rgba(26, 188, 156, 0.1)';
                break;
        }
        trendChart.update('none');
    }

    function loadTrendData(range) {
        var now = new Date();
        var chartStart = new Date();
        var useMinuteData = (range === 'realtime' || range === '1h' || range === '6h');
        switch(range) {
            case 'realtime': chartStart.setMinutes(chartStart.getMinutes() - 15); break;
            case '1h': chartStart.setHours(chartStart.getHours() - 1); break;
            case '6h': chartStart.setHours(chartStart.getHours() - 6); break;
            case '24h': chartStart.setHours(chartStart.getHours() - 24); break;
            case '7d': chartStart.setDate(chartStart.getDate() - 7); break;
        }
        var params = new URLSearchParams({ start: chartStart.toISOString(), end: now.toISOString() });
        var apiEndpoint = useMinuteData ? '/api/metrics/minute?' : '/api/metrics/hourly?';
        fetchWithErrorCount(apiEndpoint + params)
            .then(function(r) { return r.json(); })
            .then(function(resp) {
                var data = resp.data || [];
                if (!data) data = [];
                var timeField = useMinuteData ? 'time_minute' : 'time_hour';
                var filledData = fillMissingTimePoints(data, chartStart, now, range, timeField);
                var maxPoints = (range === '6h') ? 120 : 180;
                filledData = downsampleData(filledData, maxPoints);
                var labels = filledData.map(function(d) {
                    var t = new Date(d.time);
                    if (range === 'realtime' || range === '1h' || range === '6h')
                        return t.getHours() + ':' + String(t.getMinutes()).padStart(2, '0');
                    else
                        return (t.getMonth()+1) + '/' + t.getDate() + ' ' + t.getHours() + ':00';
                });
                trendChart.data.labels = labels;
                switch(currentTab) {
                    case 'requests':
                        trendChart.data.datasets[0].data = filledData.map(function(d) { return d.total_requests; });
                        trendChart.data.datasets[1].data = filledData.map(function(d) { return d.blocked_requests; });
                        break;
                    case 'qps':
                        trendChart.data.datasets[0].data = filledData.map(function(d) { return d.avg_qps; });
                        trendChart.data.datasets[1].data = filledData.map(function(d) { return d.avg_latency_ms; });
                        break;
                    case 'traffic':
                        trendChart.data.datasets[0].data = filledData.map(function(d) { return d.inbound_bytes / 1024; });
                        trendChart.data.datasets[1].data = filledData.map(function(d) { return d.outbound_bytes / 1024; });
                        break;
                }
                trendChart.update('none');
            })
            .catch(function() {});
    }

    function fillMissingTimePoints(data, startTime, endTime, range, timeField) {
        var useMinuteData = (range === 'realtime' || range === '1h' || range === '6h');
        var interval = useMinuteData ? 60000 : 3600000;
        var dataMap = {};
        var rangeStart = new Date(startTime).getTime();
        var rangeEnd = new Date(endTime).getTime();
        if (data && data.length > 0) {
            var tzOffsetMs = new Date().getTimezoneOffset() * -60000;
            var firstApiMs = new Date(data[0][timeField]).getTime();
            var needsTzFix = false;
            var tzFixMs = 0;
            var inRange = firstApiMs >= rangeStart - interval && firstApiMs <= rangeEnd + interval;
            if (!inRange && tzOffsetMs !== 0) {
                if (firstApiMs - tzOffsetMs >= rangeStart - interval && firstApiMs - tzOffsetMs <= rangeEnd + interval) {
                    needsTzFix = true;
                    tzFixMs = tzOffsetMs;
                } else if (firstApiMs + tzOffsetMs >= rangeStart - interval && firstApiMs + tzOffsetMs <= rangeEnd + interval) {
                    needsTzFix = true;
                    tzFixMs = -tzOffsetMs;
                }
            }
            data.forEach(function(d) {
                var ms = new Date(d[timeField]).getTime();
                if (needsTzFix) ms -= tzFixMs;
                var aligned = Math.floor(ms / interval) * interval;
                dataMap[aligned] = d;
            });
        }
        var result = [];
        var start = Math.floor(rangeStart / interval) * interval;
        for (var t = start; t <= rangeEnd; t += interval) {
            if (dataMap[t]) {
                var d = dataMap[t];
                result.push({ time: new Date(t), total_requests: d.total_requests, blocked_requests: d.blocked_requests, avg_qps: d.avg_qps, avg_latency_ms: d.avg_latency_ms, inbound_bytes: d.inbound_bytes || 0, outbound_bytes: d.outbound_bytes || 0 });
            } else {
                result.push({ time: new Date(t), total_requests: 0, blocked_requests: 0, avg_qps: 0, avg_latency_ms: 0, inbound_bytes: 0, outbound_bytes: 0 });
            }
        }
        return result;
    }

    function downsampleData(data, maxPoints) {
        if (!data || data.length <= maxPoints) return data;
        var interval = Math.ceil(data.length / maxPoints);
        var result = [];
        for (var i = 0; i < data.length; i += interval) {
            result.push(data[Math.min(i + interval, data.length) - 1]);
        }
        if (result[result.length - 1].time !== data[data.length - 1].time)
            result.push(data[data.length - 1]);
        return result;
    }

    function setupTimeButtons() {
        document.querySelectorAll('.time-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.time-btn').forEach(function(b) { b.classList.remove('active'); });
                btn.classList.add('active');
                currentRange = btn.dataset.range;
                loadTrendData(currentRange);
                startAutoRefresh();
            });
        });
    }

    function setupTabButtons() {
        document.querySelectorAll('.tab-btn').forEach(function(tab) {
            tab.addEventListener('click', function() {
                document.querySelectorAll('.tab-btn').forEach(function(t) { t.classList.remove('active'); });
                tab.classList.add('active');
                currentTab = tab.dataset.tab;
                updateChartConfig(currentTab);
                loadTrendData(currentRange);
            });
        });
    }

    function startAutoRefresh() {
        if (autoRefreshInterval) {
            clearInterval(autoRefreshInterval);
            var idx = intervals.indexOf(autoRefreshInterval);
            if (idx >= 0) intervals.splice(idx, 1);
        }
        var interval = currentRange === 'realtime' ? 5000 : 10000;
        autoRefreshInterval = setInterval(function() { loadTrendData(currentRange); }, interval);
        intervals.push(autoRefreshInterval);
    }

    window._dashboard.fetchConfig = fetchConfig;
    window._dashboard.fetchDetectorStatus = fetchDetectorStatus;
    window._dashboard.initCharts = initCharts;
    window._dashboard.updateChartConfig = updateChartConfig;
    window._dashboard.loadTrendData = loadTrendData;
    window._dashboard.setupTimeButtons = setupTimeButtons;
    window._dashboard.setupTabButtons = setupTabButtons;
    window._dashboard.startAutoRefresh = startAutoRefresh;
    window._dashboard.updateUptime = updateUptime;
    window._dashboard.formatTimeAgo = formatTimeAgo;
    window._dashboard.fetchWithErrorCount = fetchWithErrorCount;
})();
