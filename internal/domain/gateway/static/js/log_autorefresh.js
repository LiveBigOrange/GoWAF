(function() {
    function create(config) {
        var interval = config.interval || 30000;
        var autoStart = config.autoStart !== undefined ? config.autoStart : true;
        var onRefresh = config.onRefresh || function() {};
        var onPauseReasonChange = config.onPauseReasonChange || function() {};

        var enabled = autoStart;
        var paused = false;
        var pauseReasons = new Set();
        var timerId = null;

        function startTimer() {
            stopTimer();
            if (enabled && !paused) {
                timerId = setInterval(function() {
                    onRefresh();
                }, interval);
            }
        }

        function stopTimer() {
            if (timerId !== null) {
                clearInterval(timerId);
                timerId = null;
            }
        }

        function pause(reason) {
            pauseReasons.add(reason);
            var wasPaused = paused;
            paused = true;
            stopTimer();
            if (!wasPaused && onPauseReasonChange) {
                onPauseReasonChange(true, reason);
            }
        }

        function resume(reason) {
            pauseReasons.delete(reason);
            if (pauseReasons.size === 0) {
                paused = false;
                if (enabled) {
                    startTimer();
                }
                if (onPauseReasonChange) {
                    onPauseReasonChange(false, reason);
                }
            }
        }

        function toggle() {
            enabled = !enabled;
            if (enabled) {
                paused = false;
                pauseReasons.clear();
                startTimer();
            } else {
                stopTimer();
            }
            updateButton();
        }

        function updateButton() {
            var btn = document.getElementById('autoRefreshBtn');
            var label = document.getElementById('arLabel');
            if (!btn) return;
            if (enabled && !paused) {
                btn.classList.add('active');
                if (label) label.textContent = '自动刷新 ' + (interval / 1000) + 's';
            } else if (enabled && paused) {
                btn.classList.add('active');
                if (label) label.textContent = '已暂停(详情)';
            } else {
                btn.classList.remove('active');
                if (label) label.textContent = '已关闭';
            }
        }

        function setIntervalMs(ms) {
            interval = ms;
            if (timerId !== null) {
                startTimer();
            }
            updateButton();
        }

        if (autoStart) {
            startTimer();
        }

        return {
            start: startTimer,
            stop: stopTimer,
            pause: pause,
            resume: resume,
            toggle: toggle,
            isPaused: function() { return paused; },
            isEnabled: function() { return enabled; },
            setInterval: setIntervalMs,
            updateButton: updateButton,
            destroy: function() {
                stopTimer();
                pauseReasons.clear();
                enabled = false;
                paused = false;
            }
        };
    }

    window.LogAutoRefresh = { create: create };
})();
