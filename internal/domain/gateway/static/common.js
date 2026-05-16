// GoWAF 共享工具函数
(function() {
    'use strict';

    // P2-21 深色模式初始化
    var savedTheme = localStorage.getItem('gowaf-theme');
    if (savedTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
    }

    window.toggleTheme = function() {
        var current = document.documentElement.getAttribute('data-theme');
        if (current === 'dark') {
            document.documentElement.removeAttribute('data-theme');
            localStorage.setItem('gowaf-theme', 'light');
            var btn = document.querySelector('.theme-toggle');
            if (btn) btn.textContent = '🌙';
        } else {
            document.documentElement.setAttribute('data-theme', 'dark');
            localStorage.setItem('gowaf-theme', 'dark');
            var btn = document.querySelector('.theme-toggle');
            if (btn) btn.textContent = '☀️';
        }
    };

    // 初始化主题按钮状态
    if (savedTheme === 'dark') {
        var btn = document.querySelector('.theme-toggle');
        if (btn) btn.textContent = '☀️';
    }

    window.escapeHtml = function(text) {
        if (text == null) return '';
        text = String(text);
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    window.formatTime = function(timeStr) {
        if (!timeStr) return '-';
        try {
            var d = new Date(timeStr);
            if (isNaN(d.getTime())) return timeStr;
            var pad = function(n) { return n < 10 ? '0' + n : n; };
            return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
                ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
        } catch (e) {
            return timeStr;
        }
    };

    window.formatBytes = function(bytes) {
        if (bytes == null) return '-';
        bytes = Number(bytes);
        if (bytes === 0) return '0 B';
        if (bytes < 0) return '-';
        var units = ['B', 'KB', 'MB', 'GB', 'TB'];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        i = Math.min(i, units.length - 1);
        return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
    };

    window.formatDuration = function(seconds) {
        if (seconds == null || seconds < 0) return '-';
        seconds = Number(seconds);
        if (seconds < 60) return seconds + '秒';
        if (seconds < 3600) return Math.floor(seconds / 60) + '分钟';
        if (seconds < 86400) return Math.floor(seconds / 3600) + '小时';
        return Math.floor(seconds / 86400) + '天';
    };
})();
