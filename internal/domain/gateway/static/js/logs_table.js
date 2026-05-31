(function() {
            var allLogs = [];
            var filteredLogs = [];
            var currentPage = 1;
            var currentViewMode = 'detail';
            var pageSize = 50;
            var urlRestored = false;
            var groupCurrentPage = 1;
            var groupPageSize = 20;

            function syncURL() {
                var params = new URLSearchParams();
                params.set('view', currentViewMode);
                var method = document.getElementById('filterMethod').value;
                var action = document.getElementById('filterAction').value;
                var status = document.getElementById('filterStatus').value;
                var ip = document.getElementById('filterIP').value;
                var path = document.getElementById('filterPath').value;
                if (method) params.set('method', method);
                if (action) params.set('action', action);
                if (status) params.set('status', status);
                if (ip) params.set('ip', ip);
                if (path) params.set('path', path);
                if (currentPage > 1) params.set('page', currentPage);
                if (pageSize !== 50) params.set('size', pageSize);
                if (groupCurrentPage > 1) params.set('gpage', groupCurrentPage);
                history.replaceState(null, '', '?' + params.toString());
            }

            function restoreFromURL() {
                var params = new URLSearchParams(location.search);
                if (params.get('view')) currentViewMode = params.get('view');
                if (params.get('method')) document.getElementById('filterMethod').value = params.get('method');
                if (params.get('action')) document.getElementById('filterAction').value = params.get('action');
                if (params.get('status')) document.getElementById('filterStatus').value = params.get('status');
                if (params.get('ip')) document.getElementById('filterIP').value = params.get('ip');
                if (params.get('path')) document.getElementById('filterPath').value = params.get('path');
                var urlPage = parseInt(params.get('page')) || 1;
                if (urlPage > 1) currentPage = urlPage;
                var gpage = parseInt(params.get('gpage')) || 1;
                if (gpage > 1) groupCurrentPage = gpage;
                if (params.get('size')) {
                    var s = parseInt(params.get('size'));
                    if (s > 0) { pageSize = s; document.getElementById('pageSize').value = String(s); }
                }
                urlRestored = true;
            }
            
            function escapeHtml(text) {
                if (text == null) return '';
                var div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            // 时间格式化函数 - 将RFC3339格式转换为友好的显示格式
            function formatTime(timeStr) {
                if (!timeStr) return '-';
                try {
                    var date = new Date(timeStr);
                    if (isNaN(date.getTime())) return timeStr;

                    // 格式化为: YYYY-MM-DD HH:mm:ss
                    var year = date.getFullYear();
                    var month = String(date.getMonth() + 1).padStart(2, '0');
                    var day = String(date.getDate()).padStart(2, '0');
                    var hours = String(date.getHours()).padStart(2, '0');
                    var minutes = String(date.getMinutes()).padStart(2, '0');
                    var seconds = String(date.getSeconds()).padStart(2, '0');

                    return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
                } catch (e) {
                    return timeStr;
                }
            }

            // 字节大小格式化函数 - 转换为友好的显示格式
            function formatBytes(bytes) {
                if (!bytes || bytes === 0) return '0 B';
                var k = 1024;
                var sizes = ['B', 'KB', 'MB', 'GB'];
                var i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }
            
            window.loadLogs = function() {
                fetch('/api/logs/list?limit=5000')
                    .then(r => r.json())
                    .then(data => {
                        if (!data.success) {
                            allLogs = [];
                            document.getElementById('logBody').innerHTML = '<tr><td colspan="10" class="empty-message">' + (data.error || '加载失败') + '</td></tr>';
                            return;
                        }
                        allLogs = Array.isArray(data.data) ? data.data : [];
                        applyFilters();
                        updateStats();
                        if (currentViewMode !== 'detail') {
                            document.getElementById('detailTable').style.display = 'none';
                            document.getElementById('groupViewContainer').style.display = '';
                            document.getElementById('pagination').style.display = 'none';
                            renderGroupView();
                        }
                    })
                    .catch(err => {
                        console.error('加载日志失败:', err);
                        document.getElementById('logBody').innerHTML = '<tr><td colspan="10" class="empty-message">加载失败</td></tr>';
                    });
            }
            
            window.applyFilters = function() {
                var methodFilter = document.getElementById('filterMethod').value;
                var actionFilter = document.getElementById('filterAction').value;
                var statusFilter = document.getElementById('filterStatus').value;
                var ipFilter = document.getElementById('filterIP').value.toLowerCase().trim();
                var pathFilter = document.getElementById('filterPath').value.toLowerCase().trim();

                filteredLogs = allLogs.filter(function(log) {
                    if (methodFilter && log.method !== methodFilter) return false;

                    if (actionFilter && log.action !== actionFilter) return false;

                    if (statusFilter) {
                        var status = log.status;
                        if (statusFilter === '2xx' && (status < 200 || status >= 300)) return false;
                        else if (statusFilter === '3xx' && (status < 300 || status >= 400)) return false;
                        else if (statusFilter === '4xx' && (status < 400 || status >= 500)) return false;
                        else if (statusFilter === '5xx' && status < 500) return false;
                        else if (!isNaN(statusFilter) && status !== parseInt(statusFilter)) return false;
                    }

                    if (ipFilter && log.client_ip && log.client_ip.toLowerCase().indexOf(ipFilter) === -1) return false;
                    if (pathFilter && log.path && log.path.toLowerCase().indexOf(pathFilter) === -1) return false;

                    return true;
                });

                if (!urlRestored) currentPage = 1;
                urlRestored = false;
                detailManager.collapseAll();
                renderLogs();
                syncURL();
            }
            
            function updateStats() {
                document.getElementById('totalCount').textContent = allLogs.length;
                
                var success = allLogs.filter(function(l) { return l.status >= 200 && l.status < 400; }).length;
                var clientError = allLogs.filter(function(l) { return l.status >= 400 && l.status < 500; }).length;
                var serverError = allLogs.filter(function(l) { return l.status >= 500; }).length;
                
                document.getElementById('successCount').textContent = success;
                document.getElementById('clientErrorCount').textContent = clientError;
                document.getElementById('serverErrorCount').textContent = serverError;
            }
            
            function renderLogs() {
                var tbody = document.getElementById('logBody');
                var pagination = document.getElementById('pagination');

                if (!filteredLogs || filteredLogs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="10" class="empty-message">暂无日志记录</td></tr>';
                    pagination.style.display = 'none';
                    return;
                }

                var totalPages = Math.ceil(filteredLogs.length / pageSize);
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;

                var start = (currentPage - 1) * pageSize;
                var end = Math.min(start + pageSize, filteredLogs.length);
                var pageData = filteredLogs.slice(start, end);

                tbody.innerHTML = '';
                pageData.forEach(function(log, index) {
                    var tr = document.createElement('tr');

                    var statusClass = 'success';
                    if (log.status >= 300 && log.status < 400) statusClass = 'redirect';
                    else if (log.status >= 400 && log.status < 500) statusClass = 'client-error';
                    else if (log.status >= 500) statusClass = 'server-error';

                    var methodClass = log.method || 'GET';

                    // 地理位置显示
                    var geoDisplay = '-';
                    if (log.geo_country) {
                        geoDisplay = (log.geo_flag || '') + ' ' + log.geo_country;
                        if (log.geo_city && log.geo_city !== log.geo_country) {
                            geoDisplay += ' ' + log.geo_city;
                        }
                    }

                    // 动作显示
                    var actionClass = log.action || 'pass';
                    var actionText = actionClass === 'block' ? '拦截' : '放行';

                    tr.innerHTML =
                        '<td style="color:#7f8c8d;">' + formatTime(log.timestamp) + '</td>' +
                        '<td style="color:#e74c3c;font-weight:500;">' + escapeHtml(log.client_ip) + '</td>' +
                        '<td style="color:#7f8c8d;font-size:12px;">' + escapeHtml(geoDisplay) + '</td>' +
                        '<td><span class="method-badge ' + methodClass + '">' + escapeHtml(log.method) + '</span></td>' +
                        '<td style="color:#2c3e50;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeHtml(log.path) + '">' + escapeHtml(log.path) + '</td>' +
                        '<td><span class="action-badge ' + actionClass + '">' + actionText + '</span></td>' +
                        '<td><span class="status-badge ' + statusClass + '">' + log.status + '</span></td>' +
                        '<td style="color:#95a5a6;">' + (log.latency_ms || 0) + 'ms</td>' +
                        '<td style="color:#7f8c8d;">' + escapeHtml(log.upstream_addr || '-') + '</td>' +
                        '<td><button class="view-btn" onclick="toggleDetail(' + index + ', event)">查看详情</button></td>';

                    tbody.appendChild(tr);
                });

                document.getElementById('pageInfo').textContent = '第' + currentPage + ' 页 / 第' + totalPages + ' 页（共' + filteredLogs.length + ' 条）';
                RenderPageBtns('pageBtns', currentPage, totalPages, 'goPage');
                pagination.style.display = 'flex';
                restoreExpandedDetails();
            }
            
            window.goPage = function(p) {
                var total = Math.ceil(filteredLogs.length / pageSize);
                if (p < 1) p = 1;
                if (p > total) p = total;
                currentPage = p;
                detailManager.collapseAll();
                renderLogs();
                syncURL();
            };
            
            window.changePageSize = function() {
                pageSize = parseInt(document.getElementById('pageSize').value);
                currentPage = 1;
                detailManager.collapseAll();
                renderLogs();
                syncURL();
            };
            
            window.exportLogs = function() {
                var dataStr = JSON.stringify(filteredLogs, null, 2);
                var blob = new Blob([dataStr], { type: 'application/json' });
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url;
                var d = new Date(); a.download = 'access_logs_' + d.getFullYear() + '-' + String(d.getMonth()+1).padStart(2,'0') + '-' + String(d.getDate()).padStart(2,'0') + '.json';
                a.click();
                URL.revokeObjectURL(url);
            };

            window.toggleDetail = function(index, e) {
                var btn = e.target;
                var row = btn.closest('tr');
                var detailId = 'log-detail-' + index;
                var existingDetail = row.nextElementSibling;
                if (existingDetail && existingDetail.classList.contains('detail-row') && existingDetail.classList.contains('show')) {
                    existingDetail.remove();
                    btn.textContent = '查看详情';
                    detailManager.collapse(detailId);
                } else {
                    var start = (currentPage - 1) * pageSize;
                    var log = filteredLogs[start + index];
                    if (!log) return;
                    var detailTr = document.createElement('tr');
                    detailTr.className = 'detail-row show';
                    detailTr.setAttribute('data-detail-id', detailId);
                    detailTr.innerHTML = '<td colspan="10"><div class="detail-content">' + buildLogDetailHtml(log) + '</div></td>';
                    row.after(detailTr);
                    btn.textContent = '收起详情';
                    btn.setAttribute('data-detail-id', detailId);
                    detailManager.expand(detailId);
                }
            };

            function restoreExpandedDetails() {
                var expandedIds = detailManager.getExpandedIds();
                if (expandedIds.size === 0) return;
                expandedIds.forEach(function(detailId) {
                    var indexStr = detailId.replace('log-detail-', '');
                    var index = parseInt(indexStr);
                    if (isNaN(index)) return;
                    var start = (currentPage - 1) * pageSize;
                    var log = filteredLogs[start + index];
                    if (!log) { detailManager.collapse(detailId); return; }
                    var rows = document.getElementById('logBody').children;
                    if (index >= rows.length) return;
                    var row = rows[index];
                    var btn = row.querySelector('.view-btn');
                    var detailTr = document.createElement('tr');
                    detailTr.className = 'detail-row show';
                    detailTr.setAttribute('data-detail-id', detailId);
                    detailTr.innerHTML = '<td colspan="10"><div class="detail-content">' + buildLogDetailHtml(log) + '</div></td>';
                    row.after(detailTr);
                    if (btn) {
                        btn.textContent = '收起详情';
                        btn.setAttribute('data-detail-id', detailId);
                    }
                });
            }

            function buildLogDetailHtml(log) {
                var statusClass = 'success';
                if (log.status >= 300 && log.status < 400) statusClass = 'redirect';
                else if (log.status >= 400 && log.status < 500) statusClass = 'client-error';
                else if (log.status >= 500) statusClass = 'server-error';
                var actionClass = log.action || 'pass';
                var actionText = actionClass === 'block' ? '拦截' : '放行';
                var h = '';
                h += '<div class="detail-item"><span class="detail-label">请求ID：</span><span class="detail-value"><code>' + escapeHtml(log.request_id || '-') + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">时间戳：</span><span class="detail-value">' + formatTime(log.timestamp) + '</span></div>';
                h += '<div class="detail-item"><span class="detail-label">客户端IP：</span><span class="detail-value"><code>' + escapeHtml(log.client_ip || '-') + '</code></span></div>';
                if (log.geo_country) {
                    var dg = escapeHtml(log.geo_flag || '') + ' ' + escapeHtml(log.geo_country);
                    if (log.geo_city && log.geo_city !== log.geo_country) dg += ' ' + escapeHtml(log.geo_city);
                    h += '<div class="detail-item"><span class="detail-label">地理位置：</span><span class="detail-value">' + dg + '</span></div>';
                }
                h += '<div class="detail-item"><span class="detail-label">请求Host：</span><span class="detail-value"><code>' + escapeHtml(log.host || '-') + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">请求方法：</span><span class="detail-value"><code>' + escapeHtml(log.method || '-') + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">请求路径：</span><span class="detail-value"><code>' + escapeHtml(log.path || '-') + '</code></span></div>';
                if (log.query) h += '<div class="detail-item"><span class="detail-label">查询参数：</span><span class="detail-value"><code>' + escapeHtml(log.query) + '</code></span></div>';
                if (log.protocol) h += '<div class="detail-item"><span class="detail-label">HTTP协议：</span><span class="detail-value"><code>' + escapeHtml(log.protocol) + '</code></span></div>';
                if (log.scheme) h += '<div class="detail-item"><span class="detail-label">请求协议：</span><span class="detail-value"><code>' + escapeHtml(log.scheme) + '</code></span></div>';
                if (log.user_agent) h += '<div class="detail-item"><span class="detail-label">User-Agent：</span><span class="detail-value">' + escapeHtml(log.user_agent) + '</span></div>';
                if (log.referer) h += '<div class="detail-item"><span class="detail-label">Referer：</span><span class="detail-value">' + escapeHtml(log.referer) + '</span></div>';
                if (log.content_type) h += '<div class="detail-item"><span class="detail-label">Content-Type：</span><span class="detail-value"><code>' + escapeHtml(log.content_type) + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">处理动作：</span><span class="detail-value"><span class="action-badge ' + actionClass + '">' + actionText + '</span></span></div>';
                h += '<div class="detail-item"><span class="detail-label">状态码：</span><span class="detail-value"><span class="status-badge ' + statusClass + '">' + log.status + '</span></span></div>';
                if (log.rule_id) h += '<div class="detail-item"><span class="detail-label">规则ID：</span><span class="detail-value"><code>' + escapeHtml(log.rule_id) + '</code></span></div>';
                if (log.match_detail) {
                    var mdh = escapeHtml(log.match_detail);
                    mdh = mdh.replace(/\[Rule#(\d+)\|([^\]]+)\]/g, '<span style="background:#e8f5e9;color:#2e7d32;padding:1px 6px;border-radius:3px;font-size:11px;margin:0 2px;">规则#$1 [$2]</span>');
                    mdh = mdh.replace(/\[Rule#(\d+)\]/g, '<span style="background:#e8f5e9;color:#2e7d32;padding:1px 6px;border-radius:3px;font-size:11px;margin:0 2px;">规则#$1</span>');
                    mdh = mdh.replace(/\[([^\]]+)\]/g, function(m, content) {
                        if (content.indexOf('Rule#') === -1) return '<span style="background:#fff3e0;color:#e65100;padding:1px 6px;border-radius:3px;font-size:11px;margin:0 2px;">' + escapeHtml(content) + '</span>';
                        return m;
                    });
                    h += '<div class="detail-item"><span class="detail-label">触发子规则：</span><span class="detail-value" style="line-height:1.8;">' + mdh + '</span></div>';
                }
                if (log.match_location) h += '<div class="detail-item"><span class="detail-label">检测位置：</span><span class="detail-value"><code>' + escapeHtml(log.match_location) + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">响应延迟：</span><span class="detail-value">' + (log.latency_ms ? log.latency_ms.toFixed(2) + ' ms' : '-') + '</span></div>';
                if (log.upstream_latency_ms) h += '<div class="detail-item"><span class="detail-label">后端延迟：</span><span class="detail-value">' + log.upstream_latency_ms.toFixed(2) + ' ms</span></div>';
                if (log.latency_us) h += '<div class="detail-item"><span class="detail-label">精确延迟：</span><span class="detail-value">' + log.latency_us + ' μs</span></div>';
                if (log.request_size) h += '<div class="detail-item"><span class="detail-label">请求大小：</span><span class="detail-value">' + formatBytes(log.request_size) + '</span></div>';
                if (log.body_size) h += '<div class="detail-item"><span class="detail-label">响应大小：</span><span class="detail-value">' + formatBytes(log.body_size) + '</span></div>';
                h += '<div class="detail-item"><span class="detail-label">后端地址：</span><span class="detail-value"><code>' + escapeHtml(log.upstream_addr || '-') + '</code></span></div>';
                if (log.error_message) h += '<div class="detail-item"><span class="detail-label">错误信息：</span><span class="detail-value" style="color:#e74c3c;">' + escapeHtml(log.error_message) + '</span></div>';
                return h;
            }

            window.switchViewMode = function(mode) {
                currentViewMode = mode;
                groupCurrentPage = 1;
                var btns = document.querySelectorAll('#viewModeGroup .view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === mode);
                });
                var detailTable = document.getElementById('detailTable');
                var groupContainer = document.getElementById('groupViewContainer');
                var pagination = document.getElementById('pagination');
                if (mode === 'detail') {
                    detailTable.style.display = '';
                    groupContainer.style.display = 'none';
                    pagination.style.display = 'flex';
                    document.getElementById('groupPagination').style.display = 'none';
                    renderLogs();
                } else {
                    detailTable.style.display = 'none';
                    groupContainer.style.display = '';
                    pagination.style.display = 'none';
                    renderGroupView();
                }
                syncURL();
            };

            function renderGroupView() {
                var thead = document.getElementById('groupThead');
                var tbody = document.getElementById('groupBody');
                if (!filteredLogs || filteredLogs.length === 0) {
                    thead.innerHTML = '';
                    tbody.innerHTML = '<tr><td colspan="7" class="empty-message">暂无日志数据</td></tr>';
                    return;
                }

                var groups = {};
                if (currentViewMode === 'ip') {
                    thead.innerHTML = '<tr><th>排名</th><th>IP地址</th><th>地理位置</th><th>请求次数</th><th>涉及路径数</th><th>最近请求</th><th>操作</th></tr>';
                    filteredLogs.forEach(function(log) {
                        var key = log.client_ip || 'unknown';
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', geo: '', paths: {} };
                        groups[key].count++;
                        var t = log.timestamp || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        if (!groups[key].geo && log.geo_country) {
                            groups[key].geo = (log.geo_flag || '') + ' ' + log.geo_country;
                            if (log.geo_city && log.geo_city !== log.geo_country) groups[key].geo += ' ' + log.geo_city;
                        }
                        var p = log.path || '';
                        if (p) groups[key].paths[p] = true;
                    });
                } else if (currentViewMode === 'path') {
                    thead.innerHTML = '<tr><th>排名</th><th>请求路径</th><th>请求方式</th><th>请求次数</th><th>涉及IP数</th><th>最近请求</th><th>操作</th></tr>';
                    filteredLogs.forEach(function(log) {
                        var key = log.path || 'unknown';
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', methods: {}, ips: {} };
                        groups[key].count++;
                        var t = log.timestamp || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        var m = log.method || 'GET';
                        groups[key].methods[m] = true;
                        var ip = log.client_ip || '';
                        if (ip) groups[key].ips[ip] = true;
                    });
                } else if (currentViewMode === 'status') {
                    thead.innerHTML = '<tr><th>排名</th><th>状态码</th><th>请求次数</th><th>涉及IP数</th><th>涉及路径数</th><th>最近请求</th><th>操作</th></tr>';
                    filteredLogs.forEach(function(log) {
                        var key = String(log.status || 0);
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', ips: {}, paths: {} };
                        groups[key].count++;
                        var t = log.timestamp || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        var ip = log.client_ip || '';
                        if (ip) groups[key].ips[ip] = true;
                        var p = log.path || '';
                        if (p) groups[key].paths[p] = true;
                    });
                }

                var arr = Object.values(groups);
                arr.sort(function(a, b) { return b.count - a.count; });
                var maxCount = arr.length > 0 ? arr[0].count : 1;

                var totalGroups = arr.length;
                var groupTotalPages = Math.max(1, Math.ceil(totalGroups / groupPageSize));
                if (groupCurrentPage > groupTotalPages) groupCurrentPage = groupTotalPages;
                var gStart = (groupCurrentPage - 1) * groupPageSize;
                var gEnd = Math.min(gStart + groupPageSize, totalGroups);
                var pageArr = arr.slice(gStart, gEnd);

                tbody.innerHTML = '';
                pageArr.forEach(function(group, idx) {
                    var tr = document.createElement('tr');
                    var rank = gStart + idx + 1;
                    var barWidth = Math.max(8, Math.round((group.count / maxCount) * 100));
                    var lastTime = formatTime(group.lastTime);

                    if (currentViewMode === 'ip') {
                        var pathCount = Object.keys(group.paths).length;
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td><code>' + escapeHtml(group.key) + '</code></td>' +
                            '<td>' + (group.geo || '-') + '</td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td>' + pathCount + '-路径</td>' +
                            '<td>' + escapeHtml(lastTime) + '</td>' +
                            '<td><a class="group-drill-btn" onclick="drillDown(\'ip\',\'' + escapeHtml(group.key) + '\')">查看明细</a></td>';
                    } else if (currentViewMode === 'path') {
                        var methodArr = [];
                        for (var m in group.methods) { methodArr.push(escapeHtml(m)); }
                        var ipCount = Object.keys(group.ips).length;
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td><code>' + escapeHtml(group.key) + '</code></td>' +
                            '<td>' + methodArr.join('/') + '</td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td>' + ipCount + '-IP</td>' +
                            '<td>' + escapeHtml(lastTime) + '</td>' +
                            '<td><a class="group-drill-btn" onclick="drillDown(\'path\',\'' + escapeHtml(group.key).replace(/'/g, "\\'") + '\')">查看明细</a></td>';
                    } else if (currentViewMode === 'status') {
                        var ipCount = Object.keys(group.ips).length;
                        var pathCount = Object.keys(group.paths).length;
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td><code>' + escapeHtml(group.key) + '</code></td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td>' + ipCount + '-IP</td>' +
                            '<td>' + pathCount + '-路径</td>' +
                            '<td>' + escapeHtml(lastTime) + '</td>' +
                            '<td><a class="group-drill-btn" onclick="drillDown(\'status\',' + group.key + ')">查看明细</a></td>';
                    }
                    tbody.appendChild(tr);
                });

                var gPagination = document.getElementById('groupPagination');
                if (totalGroups > groupPageSize) {
                    document.getElementById('groupPageInfo').textContent = '第' + groupCurrentPage + ' 页 / 第' + groupTotalPages + ' 页（共' + totalGroups + ' 组）';
                    document.getElementById('groupPrevBtn').disabled = groupCurrentPage <= 1;
                    document.getElementById('groupNextBtn').disabled = groupCurrentPage >= groupTotalPages;
                    gPagination.style.display = 'flex';
                } else {
                    gPagination.style.display = 'none';
                }
            }

            window.groupPrevPage = function() {
                if (groupCurrentPage > 1) {
                    groupCurrentPage--;
                    renderGroupView();
                    syncURL();
                }
            };

            window.groupNextPage = function() {
                var totalGroups = Object.keys((function() {
                    var g = {};
                    filteredLogs.forEach(function(log) {
                        var key = currentViewMode === 'ip' ? (log.client_ip || 'unknown') : currentViewMode === 'path' ? (log.path || 'unknown') : String(log.status || 0);
                        g[key] = true;
                    });
                    return g;
                })()).length;
                var groupTotalPages = Math.max(1, Math.ceil(totalGroups / groupPageSize));
                if (groupCurrentPage < groupTotalPages) {
                    groupCurrentPage++;
                    renderGroupView();
                    syncURL();
                }
            };

            window.drillDown = function(field, value) {
                currentViewMode = 'detail';
                var btns = document.querySelectorAll('#viewModeGroup .view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === 'detail');
                });
                document.getElementById('detailTable').style.display = '';
                document.getElementById('groupViewContainer').style.display = 'none';
                document.getElementById('pagination').style.display = 'flex';
                if (field === 'ip') {
                    document.getElementById('filterIP').value = value;
                } else if (field === 'path') {
                    document.getElementById('filterPath').value = value;
                } else if (field === 'status') {
                    document.getElementById('filterStatus').value = String(value);
                    if (!document.getElementById('filterStatus').querySelector('option[value="' + value + '"]')) {
                        var opt = document.createElement('option');
                        opt.value = String(value);
                        opt.textContent = String(value);
                        document.getElementById('filterStatus').appendChild(opt);
                    }
                }
                applyFilters();
            };

            // 初始加载
            restoreFromURL();
            if (currentViewMode !== 'detail') {
                var btns = document.querySelectorAll('#viewModeGroup .view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === currentViewMode);
                });
                document.getElementById('detailTable').style.display = 'none';
                document.getElementById('groupViewContainer').style.display = '';
                document.getElementById('pagination').style.display = 'none';
            }
            loadLogs();
            
            var autoRefresh = LogAutoRefresh.create({
                interval: 30000,
                autoStart: true,
                onRefresh: function() { loadLogs(); }
            });

            var detailManager = LogDetailManager.create({
                autoRefresh: autoRefresh
            });

            window.toggleAutoRefresh = function() {
                autoRefresh.toggle();
            };

            window.addEventListener('beforeunload', function() {
                autoRefresh.destroy();
                detailManager.destroy();
            });
        })();
