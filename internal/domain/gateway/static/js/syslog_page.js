(function() {
    var currentLevel = 'all';
    var allLines = [];
    var filteredLines = [];
    var autoRefreshEnabled = true;
    var pageSize = 50;
    var currentPage = 1;

    function escapeHtml(text) {
        if (text == null) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function parseLogLevel(line) {
        if (line.indexOf('[DEBUG]') >= 0) return 'debug';
        if (line.indexOf('[INFO]') >= 0) return 'info';
        if (line.indexOf('[WARN]') >= 0) return 'warn';
        if (line.indexOf('[ERROR]') >= 0) return 'error';
        if (line.indexOf('[FATAL]') >= 0) return 'fatal';
        return 'info';
    }

    function parseLine(line) {
        var level = 'info';
        var timeStr = '';
        var rest = line;
        var timeMatch = line.match(/^(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})\s*/);
        if (timeMatch) {
            timeStr = timeMatch[1];
            rest = line.substring(timeMatch[0].length);
        }
        var levelMatch = rest.match(/^(\[(?:DEBUG|INFO|WARN|ERROR|FATAL)\])\s*/);
        var msg = rest;
        if (levelMatch) {
            level = levelMatch[1].replace(/[\[\]]/g, '').toLowerCase();
            msg = rest.substring(levelMatch[0].length);
        }
        return { time: timeStr, level: level, message: msg };
    }

    function updateStats() {
        var counts = { debug: 0, info: 0, warn: 0, error: 0, fatal: 0 };
        allLines.forEach(function(line) {
            var lv = parseLogLevel(line);
            if (counts[lv] !== undefined) counts[lv]++;
        });
        document.getElementById('totalCount').textContent = allLines.length;
        document.getElementById('debugCount').textContent = counts.debug;
        document.getElementById('infoCount').textContent = counts.info;
        document.getElementById('warnCount').textContent = counts.warn;
        document.getElementById('errorCount').textContent = counts.error;
        document.getElementById('fatalCount').textContent = counts.fatal;
    }

    function applyFilter() {
        var keyword = (document.getElementById('searchKeyword').value || '').toLowerCase();
        filteredLines = allLines;
        if (keyword) {
            filteredLines = filteredLines.filter(function(l) { return l.toLowerCase().indexOf(keyword) >= 0; });
        }
        currentPage = 1;
        renderLogs();
    }

    function applyFilterSilent() {
        var keyword = (document.getElementById('searchKeyword').value || '').toLowerCase();
        filteredLines = allLines;
        if (keyword) {
            filteredLines = filteredLines.filter(function(l) { return l.toLowerCase().indexOf(keyword) >= 0; });
        }
        renderLogs();
    }

    function renderLogs() {
        var tbody = document.getElementById('logBody');
        if (!tbody) return;
        var totalPages = Math.max(1, Math.ceil(filteredLines.length / pageSize));
        if (currentPage > totalPages) currentPage = totalPages;
        var start = (currentPage - 1) * pageSize;
        var end = Math.min(start + pageSize, filteredLines.length);
        var pageLines = filteredLines.slice(start, end);
        if (filteredLines.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="empty-message">暂无日志</td></tr>';
        } else {
            var html = '';
            pageLines.forEach(function(line) {
                var p = parseLine(line);
                html += '<tr class="level-' + p.level + '">'
                    + '<td class="log-time">' + escapeHtml(p.time) + '</td>'
                    + '<td><span class="level-badge level-' + p.level + '">' + p.level.toUpperCase() + '</span></td>'
                    + '<td class="log-msg">' + escapeHtml(p.message) + '</td>'
                    + '</tr>';
            });
            tbody.innerHTML = html;
        }
        document.getElementById('pageInfo').textContent = '第 ' + currentPage + ' 页 / 第 ' + totalPages + ' 页（共 ' + filteredLines.length + ' 条）';
        RenderPageBtns('pageBtns', currentPage, totalPages, 'goPage');
    }

    window.loadLogs = function(silent) {
        fetch('/api/syslog/list?limit=5000&level=' + currentLevel)
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success) {
                    allLines = (data.data || []).reverse();
                    updateStats();
                    if (silent) {
                        applyFilterSilent();
                    } else {
                        filteredLines = allLines;
                        applyFilter();
                    }
                }
            })
            .catch(function(err) { console.error('加载系统日志失败:', err); });
    };

    window.filterByLevel = function() {
        currentLevel = document.getElementById('filterLevel').value;
        loadLogs();
    };

    window.searchLogs = function() {
        applyFilter();
    };

    window.goPage = function(p) {
        var total = Math.max(1, Math.ceil(filteredLines.length / pageSize));
        if (p < 1) p = 1;
        if (p > total) p = total;
        currentPage = p;
        renderLogs();
    };

    window.changePageSize = function() {
        pageSize = parseInt(document.getElementById('pageSize').value) || 50;
        currentPage = 1;
        renderLogs();
    };

    var autoRefresh = LogAutoRefresh.create({
        interval: 5000,
        autoStart: true,
        onRefresh: function() { loadLogs(true); }
    });

    window.toggleAutoRefresh = function() {
        autoRefresh.toggle();
    };

    loadLogs();

    window.addEventListener('beforeunload', function() {
        autoRefresh.destroy();
    });
})();
