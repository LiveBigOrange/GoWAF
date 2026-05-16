let originalConfig = {};
        let hasChanges = false;

        function loadConfig() {
            fetch('/api/config')
                .then(r => {
                    if (!r.ok) throw new Error(`HTTP ${r.status}`);
                    return r.json();
                })
                .then(data => {
                    if (!data.success) {
                        showAlert('error', '❌ ' + (data.error || '加载失败'));
                        return;
                    }

                    var cfg = data.data || data;
                    originalConfig = JSON.parse(JSON.stringify(cfg));

                    // 安全配置
                    document.getElementById('login_max_attempts').value    = cfg.security.login.max_attempts;
                    document.getElementById('login_block_duration').value  = cfg.security.login.block_duration;
                    document.getElementById('session_ttl').value           = cfg.security.session.ttl;
                    document.getElementById('session_cleanup_interval').value = cfg.security.session.cleanup_interval;
                    document.getElementById('captcha_ttl').value           = cfg.security.captcha.ttl;
                    document.getElementById('api_limit').value             = cfg.security.rate_limit.api_limit;
                    document.getElementById('api_window').value            = cfg.security.rate_limit.api_window;

                    // 性能配置
                    document.getElementById('log_channel_size').value  = cfg.performance.log_channel_size;
                    document.getElementById('cache_size').value        = cfg.performance.cache_size;
                    document.getElementById('cache_ttl').value         = cfg.performance.cache_ttl;
                    document.getElementById('max_request_body').value  = cfg.performance.max_request_body;
                    document.getElementById('scan_buffer').value       = cfg.performance.scan_buffer;

                    // 定时任务
                    document.getElementById('health_check').value     = cfg.scheduler.health_check;
                    document.getElementById('log_flush').value        = cfg.scheduler.log_flush;
                    document.getElementById('log_cleanup').value      = cfg.scheduler.log_cleanup;
                    document.getElementById('metrics_cleanup').value  = cfg.scheduler.metrics_cleanup;
                    document.getElementById('rule_reload').value      = cfg.scheduler.rule_reload;

                    // WebSocket
                    document.getElementById('dashboard_push').value    = cfg.websocket.dashboard_push;
                    document.getElementById('log_heartbeat').value     = cfg.websocket.log_heartbeat;
                    document.getElementById('buffer_size').value       = cfg.websocket.buffer_size;
                    document.getElementById('broadcast_channel').value = cfg.websocket.broadcast_channel;
                })
                .catch(err => {
                    showAlert('error', '❌ 加载配置失败: ' + err.message);
                });
        }

        function saveConfig() {
            const btn = document.getElementById('saveBtn');
            btn.disabled = true;
            btn.innerHTML = '<span aria-hidden="true">⏳</span> 保存中...';

            const config = {
                security: {
                    login: {
                        max_attempts: parseInt(document.getElementById('login_max_attempts').value, 10),
                        block_duration: parseInt(document.getElementById('login_block_duration').value, 10)
                    },
                    session: {
                        ttl: parseInt(document.getElementById('session_ttl').value, 10),
                        cleanup_interval: parseInt(document.getElementById('session_cleanup_interval').value, 10)
                    },
                    captcha: {
                        ttl: parseInt(document.getElementById('captcha_ttl').value, 10)
                    },
                    rate_limit: {
                        api_limit: parseInt(document.getElementById('api_limit').value, 10),
                        api_window: parseInt(document.getElementById('api_window').value, 10)
                    }
                },
                performance: {
                    log_channel_size: parseInt(document.getElementById('log_channel_size').value, 10),
                    cache_size: parseInt(document.getElementById('cache_size').value, 10),
                    cache_ttl: parseInt(document.getElementById('cache_ttl').value, 10),
                    max_request_body: parseInt(document.getElementById('max_request_body').value, 10),
                    scan_buffer: parseInt(document.getElementById('scan_buffer').value, 10)
                },
                scheduler: {
                    health_check: parseInt(document.getElementById('health_check').value, 10),
                    log_flush: parseInt(document.getElementById('log_flush').value, 10),
                    log_cleanup: parseInt(document.getElementById('log_cleanup').value, 10),
                    metrics_cleanup: parseInt(document.getElementById('metrics_cleanup').value, 10),
                    rule_reload: parseInt(document.getElementById('rule_reload').value, 10)
                },
                websocket: {
                    dashboard_push: parseInt(document.getElementById('dashboard_push').value, 10),
                    log_heartbeat: parseInt(document.getElementById('log_heartbeat').value, 10),
                    buffer_size: parseInt(document.getElementById('buffer_size').value, 10),
                    broadcast_channel: parseInt(document.getElementById('broadcast_channel').value, 10)
                }
            };

            fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify(config)
            })
            .then(r => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
            })
            .then(data => {
                if (!data.success) {
                    showAlert('error', '❌ ' + (data.error || '保存失败'));
                } else {
                    showAlert('success', '✅ 配置保存成功！部分配置需要重启服务生效。');
                    hasChanges = false;
                    originalConfig = JSON.parse(JSON.stringify(config));
                    // 移除所有修改高亮
                    document.querySelectorAll('.config-changed').forEach(el => el.classList.remove('config-changed'));
                }
            })
            .catch(err => {
                showAlert('error', '❌ 保存配置失败: ' + err.message);
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerHTML = '<span aria-hidden="true">💾</span> 保存配置';
            });
        }

        function resetConfig() {
            if (!confirm('⚠️ 确定要恢复默认配置吗？这将覆盖当前所有配置。')) return;

            fetch('/api/config/reset', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': getCSRFToken()
                }
            })
            .then(r => {
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                return r.json();
            })
            .then(data => {
                if (!data.success) {
                    showAlert('error', '❌ ' + (data.error || '重置失败'));
                } else {
                    showAlert('success', '✅ 已恢复默认配置');
                    setTimeout(loadConfig, 500);
                }
            })
            .catch(err => {
                showAlert('error', '❌ 恢复默认配置失败: ' + err.message);
            });
        }

        function showAlert(type, message) {
            const alertEl = document.getElementById('alert');
            alertEl.className = `alert alert-${type}`;
            alertEl.textContent = message;
            alertEl.style.display = 'flex';
            setTimeout(() => {
                alertEl.style.display = 'none';
            }, 5000);
        }

        function getCSRFToken() {
            const csrfCookie = document.cookie.split('; ')
                .find(row => row.startsWith('csrf_token='));
            return csrfCookie ? csrfCookie.split('=')[1] : '';
        }

        document.addEventListener('DOMContentLoaded', function() {
            loadConfig();

            const inputs = document.querySelectorAll('input, select');
            inputs.forEach(input => {
                input.addEventListener('change', function() {
                    hasChanges = true;
                    this.classList.add('config-changed');
                });
            });
        });

        window.addEventListener('beforeunload', function(e) {
            if (hasChanges) {
                e.preventDefault();
                e.returnValue = '您有未保存的配置更改，确定要离开吗？';
            }
        });
