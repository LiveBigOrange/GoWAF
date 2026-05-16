(function() {
    var dashboardWS = null;
    var wsReconnectTimer = null;
    var wsConnected = false;
    var wsStatusEl = null;
    var pageVisible = true;
    var wsReconnectDelay = 3000;
    var wsMaxReconnectDelay = 30000;
    var db = window._dashboard;

    function updateWSStatus() {
        if (!wsStatusEl) {
            wsStatusEl = document.createElement('div');
            wsStatusEl.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);padding:10px 20px;border-radius:8px;z-index:9999;box-shadow:0 4px 12px rgba(0,0,0,0.15);font-size:14px;transition:opacity 0.3s;pointer-events:none;';
            document.body.appendChild(wsStatusEl);
        }
        if (wsConnected) {
            wsStatusEl.style.background = '#27ae60';
            wsStatusEl.style.color = 'white';
            wsStatusEl.textContent = 'WebSocket 已连接';
            wsStatusEl.style.opacity = '1';
            setTimeout(function() { wsStatusEl.style.opacity = '0'; }, 2000);
        } else {
            wsStatusEl.style.background = '#e67e22';
            wsStatusEl.style.color = 'white';
            wsStatusEl.textContent = 'WebSocket 断开，正在重连...';
            wsStatusEl.style.opacity = '1';
        }
    }

    function connectDashboardWS() {
        if (dashboardWS) {
            dashboardWS.onopen = null;
            dashboardWS.onmessage = null;
            dashboardWS.onerror = null;
            dashboardWS.onclose = null;
            try { dashboardWS.close(); } catch(e) {}
            dashboardWS = null;
        }

        var protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        var wsUrl = protocol + '//' + window.location.host + '/ws/dashboard';

        try {
            dashboardWS = new WebSocket(wsUrl);

            dashboardWS.onopen = function() {
                console.log('仪表盘 WebSocket 连接成功');
                wsConnected = true;
                wsReconnectDelay = 3000;
                if (db.getRequestStopped()) {
                    db.setRequestStopped(false);
                    db.setRequestFailCount(0);
                    db.startAutoRefresh();
                    db.intervals.push(setInterval(db.fetchDetectorStatus, 10000));
                }
                updateWSStatus();
            };

            dashboardWS.onmessage = function(event) {
                try {
                    var data = JSON.parse(event.data);
                    if (data.type === 'dashboard_update') {
                        handleDashboardUpdate(data);
                    }
                } catch (e) {
                    console.error('WebSocket 数据解析失败:', e);
                }
            };

            dashboardWS.onerror = function(error) {
                console.error('仪表盘 WebSocket 错误:', error);
                wsConnected = false;
                updateWSStatus();
                scheduleWSReconnect();
            };

            dashboardWS.onclose = function() {
                console.log('仪表盘 WebSocket 连接关闭');
                wsConnected = false;
                updateWSStatus();
                scheduleWSReconnect();
            };
        } catch (e) {
            console.error('WebSocket 连接失败:', e);
            wsConnected = false;
            updateWSStatus();
            scheduleWSReconnect();
        }
    }

    function handleDashboardUpdate(data) {
        if (data.stats) {
            var totalEl = document.getElementById('total');
            var blockedEl = document.getElementById('blocked');
            var qpsEl = document.getElementById('qps');
            if (totalEl) totalEl.innerText = data.stats.total || 0;
            if (blockedEl) blockedEl.innerText = data.stats.blocked || 0;
            if (qpsEl) qpsEl.innerText = typeof data.stats.qps === 'number' ? data.stats.qps.toFixed(2) : (data.stats.qps || 0);
        }

        try {
        if (data.system) {
            var d = data.system;
            var cpuEl = document.getElementById('cpuUsage');
            if (cpuEl && typeof d.cpu_usage === 'number') cpuEl.innerText = d.cpu_usage.toFixed(1) + '%';

            var memEl = document.getElementById('memUsage');
            var memPercentEl = document.getElementById('memPercent');
            if (memEl && memPercentEl) {
                var fmtMem = function(bytes) {
                    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
                    return (bytes / 1048576).toFixed(1) + ' MB';
                };
                memEl.innerText = fmtMem(d.mem_used || 0);
                memPercentEl.innerText = (typeof d.mem_percent === 'number' ? d.mem_percent.toFixed(1) : '0') + '% / ' + fmtMem(d.mem_total || 0);
            }

            var goroutinesEl = document.getElementById('goroutines');
            if (goroutinesEl) goroutinesEl.innerText = d.goroutines;

            var diskEl = document.getElementById('diskUsage');
            var diskPercentEl = document.getElementById('diskPercent');
            if (diskEl && diskPercentEl) {
                var diskGB = ((d.disk_used || 0) / 1024 / 1024 / 1024).toFixed(1);
                var diskTotalGB = ((d.disk_total || 0) / 1024 / 1024 / 1024).toFixed(1);
                diskEl.innerText = diskGB + ' GB';
                diskPercentEl.innerText = (typeof d.disk_percent === 'number' ? d.disk_percent.toFixed(1) : '0') + '% / ' + diskTotalGB + ' GB';
            }

            var numGCEl = document.getElementById('numGC');
            if (numGCEl) numGCEl.innerText = d.num_gc || 0;

            var gcPauseEl = document.getElementById('gcPause');
            if (gcPauseEl) gcPauseEl.innerText = d.gc_pause_avg ? d.gc_pause_avg.toFixed(2) + ' ms' : '0 ms';

            var heapMemEl = document.getElementById('heapMem');
            if (heapMemEl) heapMemEl.innerText = ((d.heap_alloc || 0) / 1024 / 1024).toFixed(1) + ' MB';

            var heapObjectsEl = document.getElementById('heapObjects');
            if (heapObjectsEl) heapObjectsEl.innerText = d.heap_objects || 0;

            var stackMemEl = document.getElementById('stackMem');
            if (stackMemEl) stackMemEl.innerText = ((d.stack_inuse || 0) / 1024 / 1024).toFixed(1) + ' MB';

            var numThreadEl = document.getElementById('numThread');
            if (numThreadEl) numThreadEl.innerText = d.num_thread || 0;

            var goVersionEl = document.getElementById('goVersion');
            if (goVersionEl) goVersionEl.innerText = d.go_version || '-';

            var numFDEl = document.getElementById('numFD');
            if (numFDEl) numFDEl.innerText = d.num_fd || 0;

            if (!db.getStartTime() && d.uptime) {
                db.setStartTime(Date.now() - (d.uptime * 1000));
                if (db.getUptimeInterval()) clearInterval(db.getUptimeInterval());
                db.setUptimeInterval(setInterval(db.updateUptime, 1000));
            }
            db.updateUptime();
        }
        } catch(sysErr) { console.error('system数据渲染异常:', sysErr); }

        try {
        // [封存] 情报中心数据渲染暂时禁用
        // if (data.intel) {
        //     var intel = data.intel;
        //     var panel = document.getElementById('intelPanel');
        //     if (panel) panel.style.display = '';
        //     var connEl = document.getElementById('intelConnected');
        //     if (connEl) connEl.innerHTML = intel.connected ? '<span style="color:#67c23a">● 已连接</span>' : '<span style="color:#f56c6c">● 断开</span>';
        //     var tierEl = document.getElementById('intelTier');
        //     if (tierEl) tierEl.innerText = intel.license_tier || 'free';
        //     var tcEl = document.getElementById('intelThreatCount');
        //     if (tcEl) tcEl.innerText = intel.threat_count || 0;
        //     var lsEl = document.getElementById('intelLicenseStatus');
        //     if (lsEl) {
        //         var s = intel.license_status;
        //         if (s === 'active') lsEl.innerHTML = '<span style="color:#67c23a">有效</span>';
        //         else if (s === 'grace') lsEl.innerHTML = '<span style="color:#e6a23c">宽限期</span>';
        //         else if (s === 'expired') lsEl.innerHTML = '<span style="color:#f56c6c">已过期</span>';
        //         else lsEl.innerText = s || '-';
        //     }
        //     var dlEl = document.getElementById('intelDaysLeft');
        //     if (dlEl) dlEl.innerText = intel.license_days_left != null ? intel.license_days_left + '天' : '-';
        //     var ueEl = document.getElementById('intelUploadEnabled');
        //     if (ueEl) ueEl.innerHTML = intel.upload_enabled ? '<span style="color:#67c23a">已启用</span>' : '<span style="color:#909399">未启用</span>';
        //     var ecEl = document.getElementById('intelEmergencyCount');
        //     if (ecEl) ecEl.innerText = intel.emergency_rules_active || 0;
        // }
        } catch(intelErr) { console.error('intel数据渲染异常:', intelErr); }

        try {
        if (data.business) {
            var b = data.business;
            var errorRateEl = document.getElementById('errorRate');
            if (errorRateEl) errorRateEl.innerText = b.error_rate ? b.error_rate.toFixed(2) + '%' : '0%';

            var blockRateEl = document.getElementById('blockRate');
            if (blockRateEl) blockRateEl.innerText = b.block_rate ? b.block_rate.toFixed(2) + '%' : '0%';

            var avgLatencyEl = document.getElementById('avgLatency');
            if (avgLatencyEl) avgLatencyEl.innerText = b.avg_latency ? b.avg_latency.toFixed(2) + ' ms' : '0 ms';

            var activeConnsEl = document.getElementById('activeConns');
            if (activeConnsEl) activeConnsEl.innerText = b.active_conns || 0;

            var networkIOEl = document.getElementById('networkIO');
            if (networkIOEl && b.network_in !== undefined && b.network_out !== undefined) {
                var inKB = (b.network_in / 1024).toFixed(1);
                var outKB = (b.network_out / 1024).toFixed(1);
                networkIOEl.innerText = '↓' + inKB + ' ↑' + outKB + ' KB';
            }
        }
        } catch(bizErr) { console.error('business数据渲染异常:', bizErr); }

        renderEvents(data);
        renderTopIPs(data);
        renderTopPaths(data);
        renderRuleHits(data);
    }

    function renderEvents(data) {
        var eventList = document.getElementById('events');
        if (eventList) {
            if (data.events && data.events.length > 0) {
                eventList.innerHTML = '';
                data.events.slice(0, 5).forEach(function(e) {
                    var li = document.createElement('li');
                    li.className = 'event-grid event-grid--events';
                    var timeStr = e.timestamp || e.time || '';
                    if (timeStr.length > 19) timeStr = timeStr.substring(0, 19);
                    var method = e.method || '-';
                    var status = e.status || 403;
                    var latency = e.latency_ms ? e.latency_ms.toFixed(1) + 'ms' : '-';
                    var countryText = '-';
                    if (e.geo_country && e.geo_country !== '局域网' && e.geo_country !== '未知') {
                        countryText = (e.geo_flag || '') + ' ' + e.geo_country;
                    } else if (e.geo_country && (e.geo_country === '局域网' || e.geo_country === '未知')) {
                        countryText = e.geo_country;
                    }
                    var cityText = '';
                    if (e.geo_city && e.geo_city !== e.geo_country) {
                        cityText = '-' + e.geo_city;
                    }
                    var geoDisplay = countryText + cityText;
                    li.innerHTML =
                        '<span class="col" data-label="时间">' + escapeHtml(timeStr) + '</span>' +
                        '<span class="col col--center" data-label="方法">' + escapeHtml(method) + '</span>' +
                        '<span class="col" data-label="来源IP">' + escapeHtml(e.client_ip || '-') + '</span>' +
                        '<span class="col" data-label="国家-城市">' + escapeHtml(geoDisplay) + '</span>' +
                        '<span class="col" data-label="路径" title="' + escapeHtml(e.path || '-') + '">' + escapeHtml(e.path || '-') + '</span>' +
                        '<span class="col" data-label="规则">' + escapeHtml(e.rule_id || '-') + '</span>' +
                        '<span class="col col--number" data-label="状态码">' + status + '</span>' +
                        '<span class="col col--number" data-label="延迟">' + latency + '</span>';
                    eventList.appendChild(li);
                });
            } else {
                eventList.innerHTML = '<li class="empty-message">暂无拦截事件</li>';
            }
        }
    }

    function renderTopIPs(data) {
        var topIPList = document.getElementById('topIPs');
        if (topIPList) {
            if (data.top_ips && data.top_ips.length > 0) {
                topIPList.innerHTML = '';
                data.top_ips.slice(0, 5).forEach(function(item) {
                    var li = document.createElement('li');
                    li.className = 'event-grid event-grid--ip';
                    var lastSeen = item.last_seen ? db.formatTimeAgo(item.last_seen) : '';
                    var ruleTypesStr = '';
                    if (item.rule_types && Object.keys(item.rule_types).length > 0) {
                        var ruleArr = [];
                        for (var rule in item.rule_types) {
                            ruleArr.push(escapeHtml(rule) + '(' + item.rule_types[rule] + ')');
                        }
                        ruleTypesStr = ruleArr.join(' ');
                    }
                    var riskBadge = '';
                    if (item.risk_level) {
                        var riskColor = item.risk_level === 'high' ? '#e74c3c' : (item.risk_level === 'medium' ? '#f39c12' : '#27ae60');
                        var riskText = item.risk_level === 'high' ? '高危' : (item.risk_level === 'medium' ? '中危' : '低危');
                        riskBadge = '<span style="color:' + riskColor + ';font-weight:600;font-size:11px;">' + riskText + '</span>';
                    }
                    var geoBadge = '';
                    if (item.geo_country) {
                        if (item.geo_country === '局域网' || item.geo_country === '未知') {
                            geoBadge = '<span style="font-size:12px;color:#888;" title="' + escapeHtml(item.geo_country) + '">' + escapeHtml(item.geo_country) + '</span>';
                        } else {
                            var flag = item.geo_flag || '🌐';
                            geoBadge = '<span style="font-size:12px;" title="' + escapeHtml(item.geo_country) + '">' + escapeHtml(flag) + '</span>';
                        }
                    }
                    li.innerHTML =
                        '<span class="col col--mono" data-label="IP" title="' + escapeHtml(item.name) + '">' + escapeHtml(item.name) + '</span>' +
                        '<span class="col" data-label="攻击类型">' + (ruleTypesStr || '-') + '</span>' +
                        (riskBadge ? '<span class="col" data-label="风险">' + riskBadge + '</span>' : '<span class="col"></span>') +
                        (geoBadge ? '<span class="col" data-label="位置">' + geoBadge + '</span>' : '<span class="col" data-label="位置">-</span>') +
                        '<span class="col col--number" data-label="次数">' + item.count + '次</span>' +
                        '<span class="col col--number" data-label="最近">' + (lastSeen || '-') + '</span>';
                    topIPList.appendChild(li);
                });
            } else {
                topIPList.innerHTML = '<li class="empty-message">暂无数据</li>';
            }
        }
    }

    function renderTopPaths(data) {
        var topPathList = document.getElementById('topPaths');
        if (topPathList) {
            if (data.top_paths && data.top_paths.length > 0) {
                topPathList.innerHTML = '';
                data.top_paths.slice(0, 5).forEach(function(item) {
                    var li = document.createElement('li');
                    li.className = 'event-grid event-grid--path';
                    var lastSeen = item.last_seen ? db.formatTimeAgo(item.last_seen) : '';
                    var methodsStr = '-';
                    if (item.methods && Object.keys(item.methods).length > 0) {
                        methodsStr = Object.keys(item.methods).map(function(k){return escapeHtml(k);}).join('/');
                    }
                    var ipInfo = item.source_ip_count > 0 ? '-IP' : '';
                    li.innerHTML =
                        '<span class="col" data-label="路径" title="' + escapeHtml(item.name) + '">' + escapeHtml(item.name) + '</span>' +
                        '<span class="col col--center" data-label="方式">' + methodsStr + '</span>' +
                        '<span class="col col--number" data-label="次数">' + item.count + (ipInfo ? ' ' + ipInfo : '') + '</span>' +
                        '<span class="col col--number" data-label="最近">' + (lastSeen || '-') + '</span>';
                    topPathList.appendChild(li);
                });
            } else {
                topPathList.innerHTML = '<li class="empty-message">暂无数据</li>';
            }
        }
    }

    function renderRuleHits(data) {
        var ruleHitList = document.getElementById('ruleHits');
        if (ruleHitList) {
            if (data.rule_hits && data.rule_hits.length > 0) {
                var total = data.rule_hits.reduce(function(sum, item) { return sum + item.count; }, 0);
                ruleHitList.innerHTML = '';
                var topRuleHits = data.rule_hits.slice(0, 5);
                topRuleHits.forEach(function(item) {
                    var li = document.createElement('li');
                    li.className = 'event-grid event-grid--rule';
                    var percentage = total > 0 ? ((item.count / total) * 100).toFixed(1) : 0;
                    var lastSeen = item.last_seen ? db.formatTimeAgo(item.last_seen) : '';
                    var severityBadge = '';
                    if (item.risk_level) {
                        var sevColor = item.risk_level === 'high' ? '#e74c3c' : (item.risk_level === 'medium' ? '#f39c12' : '#27ae60');
                        var sevText = item.risk_level === 'high' ? '高危' : (item.risk_level === 'medium' ? '中危' : '低危');
                        severityBadge = ' <span style="color:' + sevColor + ';font-weight:600;font-size:11px;">' + sevText + '</span>';
                    }
                    var ipInfo = item.source_ip_count > 0 ? '-IP' : '';
                    li.innerHTML =
                        '<span class="col" data-label="规则">' + escapeHtml(item.name) + severityBadge + '</span>' +
                        '<span class="col col--number" data-label="次数">' + item.count + (ipInfo ? ' ' + ipInfo : '') + '</span>' +
                        '<span class="col col--number" data-label="占比">' + percentage + '%</span>' +
                        '<span class="col col--number" data-label="最近" style="overflow:visible;">' + (lastSeen || '-') + '</span>';
                    ruleHitList.appendChild(li);
                });
            } else {
                ruleHitList.innerHTML = '<li class="empty-message">暂无数据</li>';
            }
        }
    }

    function scheduleWSReconnect() {
        if (!pageVisible || wsReconnectTimer) return;
        var delay = wsReconnectDelay;
        wsReconnectDelay = Math.min(wsReconnectDelay * 2, wsMaxReconnectDelay);
        wsReconnectTimer = setTimeout(function() {
            wsReconnectTimer = null;
            connectDashboardWS();
        }, delay);
    }

    setTimeout(function() {
        db.fetchConfig();
        db.fetchDetectorStatus();
        db.initCharts();
        db.updateChartConfig('requests');
        db.setupTimeButtons();
        db.setupTabButtons();
        db.loadTrendData('realtime');
        connectDashboardWS();
        db.startAutoRefresh();
        db.intervals.push(setInterval(db.fetchDetectorStatus, 10000));
    }, 100);

    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            pageVisible = false;
            db.intervals.forEach(function(id) { clearInterval(id); });
            db.intervals = [];
            if (db.getAutoRefreshInterval()) {
                clearInterval(db.getAutoRefreshInterval());
                db.setAutoRefreshInterval(null);
            }
            if (db.getUptimeInterval()) {
                clearInterval(db.getUptimeInterval());
                db.setUptimeInterval(null);
            }
            if (wsReconnectTimer) {
                clearTimeout(wsReconnectTimer);
                wsReconnectTimer = null;
            }
            if (dashboardWS) {
                dashboardWS.onclose = null;
                wsConnected = false;
                dashboardWS.close();
                dashboardWS = null;
            }
        } else {
            pageVisible = true;
            db.fetchDetectorStatus();
            connectDashboardWS();
            if (db.getStartTime() && !db.getUptimeInterval()) {
                db.setUptimeInterval(setInterval(db.updateUptime, 1000));
            }
            db.startAutoRefresh();
            db.intervals.push(setInterval(db.fetchDetectorStatus, 10000));
        }
    });
})();
