(function() {
            var allData = [];
            var filteredData = [];
            var currentPage = 1;
            var pageSize = 50;
            var currentViewMode = 'detail';
            var groupCurrentPage = 1;
            var groupPageSize = 20;

            function syncURL() {
                var params = new URLSearchParams();
                params.set('view', currentViewMode);
                var search = document.getElementById('searchInput').value;
                var type = document.getElementById('typeFilter').value;
                var startDate = document.getElementById('startDate').value;
                var endDate = document.getElementById('endDate').value;
                if (search) params.set('search', search);
                if (type) params.set('type', type);
                if (startDate) params.set('start', startDate);
                if (endDate) params.set('end', endDate);
                if (currentPage > 1) params.set('page', currentPage);
                if (pageSize !== 50) params.set('size', pageSize);
                if (groupCurrentPage > 1) params.set('gpage', groupCurrentPage);
                history.replaceState(null, '', '?' + params.toString());
            }

            function restoreFromURL() {
                var params = new URLSearchParams(location.search);
                if (params.get('view')) currentViewMode = params.get('view');
                if (params.get('search')) document.getElementById('searchInput').value = params.get('search');
                if (params.get('type')) document.getElementById('typeFilter').value = params.get('type');
                if (params.get('start')) document.getElementById('startDate').value = params.get('start');
                if (params.get('end')) document.getElementById('endDate').value = params.get('end');
                var urlPage = parseInt(params.get('page')) || 1;
                if (urlPage > 1) currentPage = urlPage;
                var gpage = parseInt(params.get('gpage')) || 1;
                if (gpage > 1) groupCurrentPage = gpage;
                if (params.get('size')) {
                    var s = parseInt(params.get('size'));
                    if (s > 0) { pageSize = s; document.getElementById('pageSize').value = String(s); }
                }
            }

            function escapeHtml(text) {
                if (text == null) return '';
                var div = document.createElement('div');
                div.textContent = text;
                return div.innerHTML;
            }

            function formatTime(time) {
                if (!time) return '-';
                var date = new Date(time);
                if (isNaN(date.getTime())) return time;
                return date.getFullYear() + '-' + 
                    String(date.getMonth() + 1).padStart(2, '0') + '-' + 
                    String(date.getDate()).padStart(2, '0') + ' ' + 
                    String(date.getHours()).padStart(2, '0') + ':' + 
                    String(date.getMinutes()).padStart(2, '0') + ':' + 
                    String(date.getSeconds()).padStart(2, '0');
            }

            // 格式化字节大小
            function formatBytes(bytes) {
                if (!bytes || bytes === 0) return '0 B';
                var k = 1024;
                var sizes = ['B', 'KB', 'MB', 'GB'];
                var i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            // 解析时间为Date对象
            function parseTime(time) {
                if (!time) return null;
                var date = new Date(time);
                return isNaN(date.getTime()) ? null : date;
            }

            function getUrlParam(param) {
                var urlParams = new URLSearchParams(window.location.search);
                return urlParams.get(param);
            }

            function initFilters() {
                var type = getUrlParam('type');
                if (type) {
                    if (type === 'ip' || type === 'path' || type === 'rule') {
                        switchViewMode(type);
                    } else {
                        var typeFilter = document.getElementById('typeFilter');
                        typeFilter.value = type;
                    }
                }
            }

            var serverTotal = 0;

            function loadData() {
                fetch('/api/intercepts?page=1&page_size=5000')
                    .then(r => {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    })
                    .then(d => {
                        if (d && d.success && Array.isArray(d.data)) {
                            allData = d.data;
                            serverTotal = d.total || 0;
                        } else {
                            allData = [];
                            serverTotal = 0;
                        }
                        filteredData = allData;
                        filterTable();
                    })
                    .catch(e => {
                        console.error('获取数据失败', e);
                        allData = [];
                        filteredData = [];
                        serverTotal = 0;
                        document.getElementById('tableBody').innerHTML = 
                            '<tr><td colspan="8" style="text-align:center; color:#95a5a6; padding:40px;"><div style="font-size:16px;margin-bottom:8px;">暂无拦截数据</div><div style="font-size:12px;">当前没有拦截记录</div></td></tr>';
                        document.getElementById('pagination').style.display = 'none';
                    });
            }

            window.filterTable = function() {
                var searchText = document.getElementById('searchInput').value.toLowerCase();
                var typeFilter = document.getElementById('typeFilter').value;
                var startDate = document.getElementById('startDate').value;
                var endDate = document.getElementById('endDate').value;

                var ruleTypeMap = {
                    'ip': 'IP黑名单', 'path': '路径黑名单', 'ua': 'UA黑名单',
                    'geo': '地理规则', 'method': 'HTTP方法限制',
                    'ratelimit': '限流', 'sql': '攻击检测:sql_injection',
                    'xss': '攻击检测:xss', 'cmd': '攻击检测:command_injection',
                    'path_traversal': '攻击检测:path_traversal', 'header_injection': '攻击检测:header_injection',
                    'sensitive_data': '攻击检测:sensitive_data'
                };

                filteredData = allData.filter(function(item) {
                    var matchesSearch = !searchText || 
                        (item.client_ip && item.client_ip.toLowerCase().includes(searchText)) ||
                        (item.path && item.path.toLowerCase().includes(searchText)) ||
                        (item.rule_id && item.rule_id.toLowerCase().includes(searchText));
                    
                    var matchesType = false;
                    if (!typeFilter) matchesType = true;
                    else if (typeFilter === 'rule') matchesType = item.rule_id && item.rule_id !== '限流' && !item.rule_id.startsWith('限流');
                    else {
                        var targetRule = ruleTypeMap[typeFilter];
                        if (targetRule) matchesType = item.rule_id && (item.rule_id === targetRule || item.rule_id.startsWith(targetRule));
                        else matchesType = item.rule_id && item.rule_id === typeFilter;
                    }
                    
                    var matchesTime = true;
                    if (startDate || endDate) {
                        var itemDate = parseTime(item.timestamp || item.time);
                        if (itemDate) {
                            if (startDate) {
                                var start = new Date(startDate);
                                start.setHours(0, 0, 0, 0);
                                matchesTime = matchesTime && itemDate >= start;
                            }
                            if (endDate) {
                                var end = new Date(endDate);
                                end.setHours(23, 59, 59, 999);
                                matchesTime = matchesTime && itemDate <= end;
                            }
                        }
                    }
                    
                    return matchesSearch && matchesType && matchesTime;
                });

                currentPage = 1;
                if (currentViewMode === 'detail') {
                    renderData();
                } else {
                    renderGroupView();
                }
            };

            window.clearFilters = function() {
                document.getElementById('searchInput').value = '';
                document.getElementById('typeFilter').value = '';
                document.getElementById('startDate').value = '';
                document.getElementById('endDate').value = '';
                filteredData = allData;
                currentPage = 1;
                if (currentViewMode === 'detail') {
                    renderData();
                } else {
                    renderGroupView();
                }
            };

            function renderData() {
                var tbody = document.getElementById('tableBody');
                var pagination = document.getElementById('pagination');

                if (!filteredData || filteredData.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:#95a5a6; padding:40px;"><div style="font-size:16px;margin-bottom:8px;">暂无拦截数据</div><div style="font-size:12px;">当前没有拦截记录</div></td></tr>';
                    pagination.style.display = 'none';
                    return;
                }

                var totalPages = Math.ceil(filteredData.length / pageSize);
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;

                var start = (currentPage - 1) * pageSize;
                var end = Math.min(start + pageSize, filteredData.length);
                var pageData = filteredData.slice(start, end);

                tbody.innerHTML = '';
                pageData.forEach(function(item, index) {
                    var tr = document.createElement('tr');
                    var escapedIP = escapeHtml(item.client_ip || '');
                    var escapedPath = escapeHtml(item.path || '');
                    var escapedRule = escapeHtml(item.rule_id || '');  // 使用rule_id
                    var escapedMethod = escapeHtml(item.method || 'GET');
                    var escapedStatus = escapeHtml(item.status || 403);
                    var timeStr = formatTime(item.timestamp);  // 使用timestamp
                    
                    var ruleTypeText = '';
                    var ruleClass = '';
                    if (item.rule_id === 'IP黑名单') { ruleTypeText = 'IP黑名单'; ruleClass = 'ip'; }
                    else if (item.rule_id === 'UA黑名单') { ruleTypeText = 'UA黑名单'; ruleClass = 'ua'; }
                    else if (item.rule_id === '路径黑名单') { ruleTypeText = '路径黑名单'; ruleClass = 'path'; }
                    else if (item.rule_id === '限流') { ruleTypeText = '限流'; ruleClass = 'ratelimit'; }
                    else { ruleTypeText = escapedRule; ruleClass = 'other'; }

                    var geoText = '-';
                    if (item.geo_country) {
                        geoText = escapeHtml(item.geo_flag || '') + ' ' + escapeHtml(item.geo_country);
                        if (item.geo_city && item.geo_city !== item.geo_country) {
                            geoText += ' ' + escapeHtml(item.geo_city);
                        }
                    }

                    tr.innerHTML = '<td>' + escapeHtml(timeStr) + '</td>' +
                        '<td><code>' + escapedIP + '</code></td>' +
                        '<td>' + geoText + '</td>' +
                        '<td>' + escapedMethod + '</td>' +
                        '<td><code>' + escapedPath + '</code></td>' +
                        '<td><span class="badge ' + ruleClass + '">' + ruleTypeText + '</span></td>' +
                        '<td>' + escapedStatus + '</td>' +
                        '<td><button class="view-btn" onclick="toggleDetail(' + index + ', event)">查看详情</button></td>';
                    tbody.appendChild(tr);
                });

                document.getElementById('pageInfo').textContent = '第' + currentPage + ' 页 / 第' + totalPages + ' 页（共' + (serverTotal > filteredData.length ? serverTotal : filteredData.length) + ' 条）';
                RenderPageBtns('pageBtns', currentPage, totalPages, 'goPage');
                pagination.style.display = 'flex';
            }

            window.goPage = function(p) { var total = Math.ceil((serverTotal > filteredData.length ? serverTotal : filteredData.length) / pageSize); if (p < 1) p = 1; if (p > total) p = total; currentPage = p; if (detailManager) detailManager.collapseAll(); renderData(); };
            window.changePageSize = function() { pageSize = parseInt(document.getElementById('pageSize').value); currentPage = 1; if (detailManager) detailManager.collapseAll(); renderData(); };

            window.toggleDetail = function(index, e) {
                var btn = e.target;
                var row = btn.closest('tr');
                var detailId = 'intercept-detail-' + index;
                var existingDetail = row.nextElementSibling;
                if (existingDetail && existingDetail.classList.contains('detail-row') && existingDetail.classList.contains('show')) {
                    existingDetail.remove();
                    btn.textContent = '查看详情';
                    if (detailManager) detailManager.collapse(detailId);
                } else {
                    var start = (currentPage - 1) * pageSize;
                    var item = filteredData[start + index];
                    if (!item) return;
                    var detailTr = document.createElement('tr');
                    detailTr.className = 'detail-row show';
                    detailTr.setAttribute('data-detail-id', detailId);
                    var detailHtml = buildDetailHtml(item);
                    detailTr.innerHTML = '<td colspan="8"><div class="detail-content">' + detailHtml + '</div></td>';
                    row.after(detailTr);
                    btn.textContent = '收起详情';
                    btn.setAttribute('data-detail-id', detailId);
                    if (detailManager) detailManager.expand(detailId);
                }
            };

            function buildDetailHtml(item) {
                var timeStr = formatTime(item.timestamp);
                var escapedIP = escapeHtml(item.client_ip || '');
                var escapedPath = escapeHtml(item.path || '');
                var escapedRule = escapeHtml(item.rule_id || '');
                var escapedMethod = escapeHtml(item.method || 'GET');
                var escapedStatus = escapeHtml(item.status || 403);
                var ruleTypeText = '';
                var ruleClass = '';
                if (item.rule_id === 'IP黑名单') { ruleTypeText = 'IP黑名单'; ruleClass = 'ip'; }
                else if (item.rule_id === 'UA黑名单') { ruleTypeText = 'UA黑名单'; ruleClass = 'ua'; }
                else if (item.rule_id === '路径黑名单') { ruleTypeText = '路径黑名单'; ruleClass = 'path'; }
                else if (item.rule_id === '限流') { ruleTypeText = '限流'; ruleClass = 'ratelimit'; }
                else { ruleTypeText = escapedRule; ruleClass = 'other'; }

                var h = '';
                h += '<div class="detail-item"><span class="detail-label">请求ID：</span><span class="detail-value"><code>' + escapeHtml(item.request_id || '-') + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">拦截时间：</span><span class="detail-value">' + escapeHtml(timeStr) + '</span></div>';
                h += '<div class="detail-item"><span class="detail-label">客户端IP：</span><span class="detail-value"><code>' + escapedIP + '</code></span></div>';
                if (item.geo_country) {
                    var dg = escapeHtml(item.geo_flag || '') + ' ' + escapeHtml(item.geo_country);
                    if (item.geo_city && item.geo_city !== item.geo_country) dg += ' ' + escapeHtml(item.geo_city);
                    h += '<div class="detail-item"><span class="detail-label">地理位置：</span><span class="detail-value">' + dg + '</span></div>';
                }
                h += '<div class="detail-item"><span class="detail-label">请求Host：</span><span class="detail-value"><code>' + escapeHtml(item.host || '-') + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">请求方法：</span><span class="detail-value"><code>' + escapedMethod + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">请求路径：</span><span class="detail-value"><code>' + escapedPath + '</code></span></div>';
                if (item.query) h += '<div class="detail-item"><span class="detail-label">查询参数：</span><span class="detail-value"><code>' + escapeHtml(item.query) + '</code></span></div>';
                if (item.protocol) h += '<div class="detail-item"><span class="detail-label">HTTP协议：</span><span class="detail-value"><code>' + escapeHtml(item.protocol) + '</code></span></div>';
                if (item.scheme) h += '<div class="detail-item"><span class="detail-label">请求协议：</span><span class="detail-value"><code>' + escapeHtml(item.scheme) + '</code></span></div>';
                if (item.user_agent) h += '<div class="detail-item"><span class="detail-label">User-Agent：</span><span class="detail-value">' + escapeHtml(item.user_agent) + '</span></div>';
                if (item.referer) h += '<div class="detail-item"><span class="detail-label">Referer：</span><span class="detail-value">' + escapeHtml(item.referer) + '</span></div>';
                if (item.content_type) h += '<div class="detail-item"><span class="detail-label">Content-Type：</span><span class="detail-value"><code>' + escapeHtml(item.content_type) + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">拦截规则：</span><span class="detail-value"><span class="badge ' + ruleClass + '">' + ruleTypeText + '</span></span></div>';
                if (item.match_detail) {
                    var mdh = escapeHtml(item.match_detail);
                    mdh = mdh.replace(/\[Rule#(\d+)\|([^\]]+)\]/g, '<span style="background:#e8f5e9;color:#2e7d32;padding:1px 6px;border-radius:3px;font-size:11px;margin:0 2px;">规则#$1 [$2]</span>');
                    mdh = mdh.replace(/\[Rule#(\d+)\]/g, '<span style="background:#e8f5e9;color:#2e7d32;padding:1px 6px;border-radius:3px;font-size:11px;margin:0 2px;">规则#$1</span>');
                    mdh = mdh.replace(/\[([^\]]+)\]/g, function(m, content) {
                        if (content.indexOf('Rule#') === -1) return '<span style="background:#fff3e0;color:#e65100;padding:1px 6px;border-radius:3px;font-size:11px;margin:0 2px;">' + escapeHtml(content) + '</span>';
                        return m;
                    });
                    h += '<div class="detail-item"><span class="detail-label">触发子规则：</span><span class="detail-value" style="line-height:1.8;">' + mdh + '</span></div>';
                }
                if (item.match_location) h += '<div class="detail-item"><span class="detail-label">检测位置：</span><span class="detail-value"><code>' + escapeHtml(item.match_location) + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">状态码：</span><span class="detail-value"><code>' + escapedStatus + '</code></span></div>';
                h += '<div class="detail-item"><span class="detail-label">延迟时间：</span><span class="detail-value">' + (item.latency_ms ? item.latency_ms.toFixed(2) + ' ms' : '-') + '</span></div>';
                if (item.upstream_latency_ms) h += '<div class="detail-item"><span class="detail-label">后端延迟：</span><span class="detail-value">' + item.upstream_latency_ms.toFixed(2) + ' ms</span></div>';
                if (item.request_size) h += '<div class="detail-item"><span class="detail-label">请求大小：</span><span class="detail-value">' + formatBytes(item.request_size) + '</span></div>';
                if (item.upstream_addr) h += '<div class="detail-item"><span class="detail-label">后端地址：</span><span class="detail-value"><code>' + escapeHtml(item.upstream_addr) + '</code></span></div>';
                if (item.error_message) h += '<div class="detail-item"><span class="detail-label">错误信息：</span><span class="detail-value" style="color:#e74c3c;">' + escapeHtml(item.error_message) + '</span></div>';
                return h;
            }

            window.switchViewMode = function(mode) {
                currentViewMode = mode;
                groupCurrentPage = 1;
                var btns = document.querySelectorAll('.view-mode-btn');
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
                    renderData();
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
                if (!filteredData || filteredData.length === 0) {
                    thead.innerHTML = '';
                    tbody.innerHTML = '<tr><td colspan="7" class="empty-message">暂无拦截数据</td></tr>';
                    return;
                }

                var groups = {};
                var getKey, getLabel, getExtraInfo;
                if (currentViewMode === 'ip') {
                    thead.innerHTML = '<tr><th>排名</th><th>IP地址</th><th>地理位置</th><th>拦截次数</th><th>涉及规则</th><th>最近拦截</th><th>操作</th></tr>';
                    filteredData.forEach(function(item) {
                        var key = item.client_ip || 'unknown';
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', geo: '', rules: {} };
                        groups[key].count++;
                        var t = item.timestamp || item.time || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        if (!groups[key].geo && item.geo_country) {
                            groups[key].geo = (item.geo_flag || '') + ' ' + item.geo_country;
                            if (item.geo_city && item.geo_city !== item.geo_country) groups[key].geo += ' ' + item.geo_city;
                        }
                        var rule = item.rule_id || 'unknown';
                        groups[key].rules[rule] = (groups[key].rules[rule] || 0) + 1;
                    });
                } else if (currentViewMode === 'path') {
                    thead.innerHTML = '<tr><th>排名</th><th>请求路径</th><th>请求方式</th><th>拦截次数</th><th>涉及IP数</th><th>最近拦截</th><th>操作</th></tr>';
                    filteredData.forEach(function(item) {
                        var key = item.path || 'unknown';
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', methods: {}, ips: {} };
                        groups[key].count++;
                        var t = item.timestamp || item.time || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        var m = item.method || 'GET';
                        groups[key].methods[m] = true;
                        var ip = item.client_ip || '';
                        if (ip) groups[key].ips[ip] = true;
                    });
                } else if (currentViewMode === 'rule') {
                    thead.innerHTML = '<tr><th>排名</th><th>规则名称</th><th>命中次数</th><th>涉及IP数</th><th>最近命中</th><th>操作</th></tr>';
                    filteredData.forEach(function(item) {
                        var key = item.rule_id || 'unknown';
                        if (!groups[key]) groups[key] = { key: key, count: 0, lastTime: '', ips: {} };
                        groups[key].count++;
                        var t = item.timestamp || item.time || '';
                        if (!groups[key].lastTime || t > groups[key].lastTime) groups[key].lastTime = t;
                        var ip = item.client_ip || '';
                        if (ip) groups[key].ips[ip] = true;
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
                        var ruleArr = [];
                        for (var r in group.rules) { ruleArr.push(escapeHtml(r) + '(' + group.rules[r] + ')'); }
                        var ruleStr = ruleArr.length > 3 ? ruleArr.slice(0, 3).join(', ') + '...' : ruleArr.join(', ');
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td><code>' + escapeHtml(group.key) + '</code></td>' +
                            '<td>' + (group.geo || '-') + '</td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td style="font-size:12px;">' + ruleStr + '</td>' +
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
                    } else if (currentViewMode === 'rule') {
                        var ipCount = Object.keys(group.ips).length;
                        tr.innerHTML = '<td>' + rank + '</td>' +
                            '<td>' + escapeHtml(group.key) + '</td>' +
                            '<td>' + group.count + ' <span class="count-bar" style="width:' + barWidth + 'px;"></span></td>' +
                            '<td>' + ipCount + '-IP</td>' +
                            '<td>' + escapeHtml(lastTime) + '</td>' +
                            '<td><a class="group-drill-btn" onclick="drillDown(\'rule\',\'' + escapeHtml(group.key).replace(/'/g, "\\'") + '\')">查看明细</a></td>';
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
                    filteredData.forEach(function(item) {
                        var key = currentViewMode === 'ip' ? (item.client_ip || 'unknown') : currentViewMode === 'path' ? (item.path || 'unknown') : (item.rule_id || 'unknown');
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
                var btns = document.querySelectorAll('.view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === 'detail');
                });
                document.getElementById('detailTable').style.display = '';
                document.getElementById('groupViewContainer').style.display = 'none';
                document.getElementById('pagination').style.display = 'flex';
                document.getElementById('groupPagination').style.display = 'none';
                document.getElementById('searchInput').value = value;
                filterTable();
                syncURL();
            };

            restoreFromURL();
            if (currentViewMode !== 'detail') {
                var btns = document.querySelectorAll('.view-mode-btn');
                btns.forEach(function(btn) {
                    btn.classList.toggle('active', btn.getAttribute('data-mode') === currentViewMode);
                });
                document.getElementById('detailTable').style.display = 'none';
                document.getElementById('groupViewContainer').style.display = '';
                document.getElementById('pagination').style.display = 'none';
            }
            initFilters();
            loadData();

            var autoRefresh = LogAutoRefresh.create({
                interval: 30000,
                autoStart: false,
                onRefresh: function() { loadData(); }
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
