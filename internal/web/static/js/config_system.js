var currentSection = '';
var configData = {};
var configDefaults = {};
var savingUILock = false;
var apikeys = [];

var SECTION = {
    security: { api: '/api/config/security', save: '/api/config/security', reset: '/api/config/security/reset', icon: '&#128274;', title: '安全配置', cls: '' },
    performance: { api: '/api/config/performance', save: '/api/config/performance', reset: '/api/config/performance/reset', icon: '&#9889;', title: '性能配置', cls: '' },
    scheduler: { api: '/api/config/scheduler', save: '/api/config/scheduler', reset: '/api/config/scheduler/reset', icon: '&#9200;', title: '定时任务', cls: '' },
    websocket: { api: '/api/config/websocket', save: '/api/config/websocket', reset: '/api/config/websocket/reset', icon: '&#128225;', title: 'WebSocket', cls: '' },
    proxy: { api: '/api/config/trusted-proxies', save: '/api/config/trusted-proxies', reset: null, icon: '&#128272;', title: '可信代理列表', cls: 'modal-box-wide' },
    log: { api: '/api/config/log', save: '/api/config/log', reset: '/api/config/log/reset', icon: '&#128196;', title: '日志配置', cls: '' },
    whitelist: { api: '/api/config/admin-whitelist', save: '/api/config/admin-whitelist', reset: null, icon: '&#128737;', title: '管理IP白名单', cls: 'modal-box-wide' },
    apikey: { api: '/api/config/apikeys', save: null, reset: null, icon: '&#128273;', title: 'API密钥管理', cls: 'modal-box-wide' },
    password: { api: null, save: '/api/admin/change-password', reset: null, icon: '&#128273;', title: '修改密码', cls: 'modal-box-wide' },
    backup: { api: null, save: null, reset: null, icon: '&#128229;', title: '配置备份/还原', cls: 'modal-box-wide' },
    geoip: { api: '/api/geoip/update/config', save: '/api/geoip/update/config/save', reset: null, icon: '&#127758;', title: 'GeoIP 更新配置', cls: '' },

    global: { api: '/api/config/global-enabled', save: '/api/config/global-enabled', reset: null, icon: '&#128264;', title: '全局总开关', cls: '' }
};

function saveCurrent() {
    if (!currentSection || savingUILock) return;
    var data = collectData(currentSection);
    if (!data) return;
    var url = SECTION[currentSection].save;
    var btn = document.getElementById('configModal').querySelector('.btn-submit');
    savingUILock = true;
    btn.disabled = true;
    btn.textContent = '\u23F3 保存中...';
    fetch(url, {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify(data)})
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function(resp) {
            if (resp.success) {
                showToast('success','配置已保存');
                loadSection(currentSection, function() {
                    closeModal();
                    savingUILock = false;
                });
            } else {
                showToast('error', resp.error || '保存失败');
                btn.disabled = false;
                btn.textContent = '\uD83D\uDCBE 保存配置';
                savingUILock = false;
            }
        }).catch(function(e){
            showToast('error', e.message || '请求失败，请重试');
            btn.disabled = false;
            btn.textContent = '\uD83D\uDCBE 保存配置';
            savingUILock = false;
        });
}

function loadAll() {
    var fetches = [
        function(){return fetch('/api/config/security').then(r=>r.json()).then(function(resp){configData.security=(resp.success?resp.data:null)||{};configDefaults.security=JSON.parse(JSON.stringify(configData.security));updateSummary('security',configData.security)})},
        function(){return fetch('/api/config/performance').then(r=>r.json()).then(function(resp){configData.performance=(resp.success?resp.data:null)||{};configDefaults.performance=JSON.parse(JSON.stringify(configData.performance));updateSummary('performance',configData.performance)})},
        function(){return fetch('/api/config/scheduler').then(r=>r.json()).then(function(resp){configData.scheduler=(resp.success?resp.data:null)||{};configDefaults.scheduler=JSON.parse(JSON.stringify(configData.scheduler));updateSummary('scheduler',configData.scheduler)})},
        function(){return fetch('/api/config/websocket').then(r=>r.json()).then(function(resp){configData.websocket=(resp.success?resp.data:null)||{};configDefaults.websocket=JSON.parse(JSON.stringify(configData.websocket));updateSummary('websocket',configData.websocket)})},
        function(){return fetch('/api/config/trusted-proxies').then(r=>r.json()).then(function(resp){configData.proxy=(resp.success?resp.data:null)||{};updateSummary('proxy',configData.proxy)})},
        function(){return fetch('/api/config/log').then(r=>r.json()).then(function(resp){configData.log=(resp.success?resp.data:null)||{};configDefaults.log=JSON.parse(JSON.stringify(configData.log));updateSummary('log',configData.log)})},
        function(){return fetch('/api/config/admin-whitelist').then(r=>r.json()).then(function(resp){configData.whitelist=(resp.success?resp.data:null)||{};updateSummary('whitelist',configData.whitelist)})},
        function(){return fetch('/api/config/apikeys').then(r=>r.json()).then(function(resp){apikeys=(resp.success&&resp.data&&resp.data.keys)||[];updateSummary('apikey',{})})},
        function(){return fetch('/api/geoip/update/config').then(r=>r.json()).then(function(resp){configData.geoip=(resp.success?resp.data:null)||{};configDefaults.geoip=JSON.parse(JSON.stringify(configData.geoip));updateSummary('geoip',configData.geoip)})},
        function(){return fetch('/api/config/global-enabled').then(r=>r.json()).then(function(resp){configData.global=(resp.success?resp.data:null)||{};updateSummary('global',configData.global)})}
    ];
    // 分批加载，每批3个，间隔80ms，避免触发限流
    var i = 0;
    function next() {
        var batch = fetches.slice(i, i+3);
        if (batch.length === 0) return;
        i += 3;
        Promise.all(batch.map(function(f){return f().catch(function(){})})).then(function(){
            setTimeout(next, 80);
        });
    }
    next();
}

function loadSection(section, callback) {
    if (!SECTION[section] || !SECTION[section].api) { if (callback) callback(); return; }
    if (section === 'apikey') { if (callback) callback(); return; }
    fetch(SECTION[section].api).then(function(r) { return r.json(); }).then(function(resp) {
        var data = resp.data || {};
        configData[section] = data;
        configDefaults[section] = JSON.parse(JSON.stringify(data));
        updateSummary(section, data);
        if (callback) callback();
    }).catch(function(){
        if (callback) callback();
    });
}

function updateSummary(section, data) {
    var el = document.getElementById('summary-' + section);
    if (!el) return;
    var p = [];
    switch(section) {
        case 'security':
            p.push('登录<b>'+(data.login||{}).max_attempts+'</b>次锁定<em>'+(data.login||{}).block_duration+'min</em>');
            p.push('会话<b>'+(data.session||{}).ttl+'</b>h');
            p.push('API限流<b>'+(data.rate_limit||{}).api_limit+'</b>次');
            var ss = data.session_safe || {};
            p.push(ss.ua_detection_enabled !== false ? 'UA检测<em>开</em>' : 'UA检测<em>关</em>');
            var powVal = data.pow_difficulty || '4';
            p.push('PoW<b>'+powVal+'</b>/6');
            break;
        case 'performance':
            p.push('日志通道<b>'+(data.log_channel_size||10000)+'</b>');
            p.push('缓存<b>'+(data.cache_size||1000)+'</b>条');
            p.push('请求体<b>'+(data.max_request_body||10)+'</b>MB');
            break;
        case 'scheduler':
            p.push('健康检查<b>'+(data.health_check||5)+'</b>s');
            p.push('日志刷盘<b>'+(data.log_flush||2)+'</b>s');
            p.push('清理<b>'+((data.log_cleanup||86400)/3600).toFixed(0)+'</b>h');
            break;
        case 'websocket':
            p.push('推送<b>'+(data.dashboard_push||2)+'</b>s');
            p.push('心跳<b>'+(data.log_heartbeat||30)+'</b>s');
            p.push('缓冲<b>'+(data.buffer_size||1024)+'</b>');
            break;
        case 'proxy':
            var proxies = data.proxies || [];
            p.push(proxies.length > 0 ? '已配置<b>'+proxies.length+'</b>个可信代理' : '未配置，默认信任<em>localhost</em>');
            break;
        case 'log':
            p.push('级别<b>'+(data.level||'info')+'</b>');
            p.push('轮转<b>'+(data.max_size||100)+'</b>MB');
            p.push('保留<b>'+(data.max_age||7)+'</b>天');
            var ret = data.retention || {};
            p.push('日志保留<b>'+(ret.log_retention_days||30)+'</b>天');
            break;
        case 'whitelist':
            var cidrs = data.cidrs || [];
            p.push(cidrs.length > 0 ? '已配置<b>'+cidrs.length+'</b>条规则' : '未配置，默认允许<em>本地</em>');
            break;
        case 'apikey':
            p.push('已创建<b>'+apikeys.length+'</b>个密钥');
            break;
        case 'backup':
            p.push('备份 <b>全部配置</b> 到文件');
            break;
        case 'geoip':
            p.push('上传文件更新');
            if (data.last_update_time) p.push('上次更新 <b>'+formatDate(data.last_update_time)+'</b>');
            break;
        case 'global':
            p.push(data.enabled ? 'WAF <em style="color:#52c41a">运行中</em>' : 'WAF <em style="color:#f56c6c">已暂停</em>');
            break;
    }
    el.innerHTML = p.join(' &middot; ');
}

function openModal(section) {
    currentSection = section;
    var meta = SECTION[section];
    document.getElementById('modalTitle').innerHTML = meta.icon + ' ' + meta.title;
    var box = document.getElementById('configModalBox');
    if (meta.cls) box.className = meta.cls; else box.className = 'modal-box';

    if (section === 'password') {
        document.getElementById('modalBody').innerHTML = buildPasswordForm();
        document.getElementById('modalFoot').innerHTML =
            '<button class="btn btn-ghost" onclick="closeModal()">取消</button>' +
            '<button class="btn btn-submit" onclick="changePassword()">&#128190; 修改密码</button>';
    } else if (section === 'proxy') {
        buildProxyModal();
        return;
    } else if (section === 'whitelist') {
        buildWhitelistModal();
        return;
    } else if (section === 'apikey') {
        buildApiKeyModal();
        return;
    } else if (section === 'backup') {
        buildBackupModal();
        return;
    } else if (section === 'global') {
        buildGlobalModal();
        return;
    } else if (section === 'geoip') {
        buildGeoIPModal();
        return;
    } else if (meta.save) {
        document.getElementById('modalBody').innerHTML = buildEditor(section, configData[section] || {});
        var footBtns = '<button class="btn btn-ghost" onclick="closeModal()">取消</button>';
        if (meta.reset) footBtns += '<button class="btn btn-danger-o" onclick="resetCurrent()">&#8634; 恢复默认</button>';
        footBtns += '<button class="btn btn-submit" onclick="saveCurrent()">&#128190; 保存配置</button>';
        document.getElementById('modalFoot').innerHTML = footBtns;
    } else {
        document.getElementById('modalBody').innerHTML = '<p>暂无配置</p>';
        document.getElementById('modalFoot').innerHTML = '<button class="btn btn-ghost" onclick="closeModal()">关闭</button>';
    }

    document.getElementById('configModal').classList.add('show');
}

function buildEditor(section, d) {
    switch(section) {
        case 'security':
            var ssData = d.session_safe || {};
            return '<div class="form-section"><h4><span class="dot"></span>登录保护</h4><div class="form-grid-2">'+
                field('login_max_attempts','最大尝试次数','次',(d.login||{}).max_attempts||5,'达到后临时锁定IP')+
                field('login_block_duration','锁定时间','分钟',(d.login||{}).block_duration||15,'锁定持续时长')+
                '</div></div>'+
                '<div class="form-section"><h4><span class="dot"></span>会话管理</h4><div class="form-grid-2">'+
                field('session_ttl','会话有效期','小时',(d.session||{}).ttl||8,'超时需重新登录')+
                field('session_cleanup','清理间隔','分钟',(d.session||{}).cleanup_interval||5,'过期会话清理频率')+
                '</div></div>'+
                '<div class="form-section"><h4><span class="dot"></span>会话安全检测</h4><div class="form-grid-2">'+
                field('sessionsafe_ip_threshold','IP变化告警阈值','次',ssData.ip_mutation_threshold||3,'同一会话IP变化超过此次数触发告警')+
                '<div class="fg"><label>UA变化检测</label><select id="fld-sessionsafe_ua_enabled">'+
                '<option value="true"'+(ssData.ua_detection_enabled!==false?' selected':'')+'>开启 - 检测User-Agent变化</option>'+
                '<option value="false"'+(ssData.ua_detection_enabled===false?' selected':'')+'>关闭 - 不检测UA变化</option>'+
                '</select><div class="unit">会话中UA完全改变可能表明会话劫持</div></div>'+
                '</div></div>'+
                '<div class="form-section"><h4><span class="dot"></span>PoW 反机器人难度</h4>'+
                '<p style="font-size:12px;color:#909399;margin:0 0 12px;line-height:1.6">控制JS挑战（验证码类反爬）的计算难度。值越大客户端计算时间越长，机器人越难通过，但影响正常用户体验。</p>'+
                '<div class="form-grid-2">'+
                '<div class="fg"><label>难度等级</label><select id="fld-pow_difficulty">'+
                [1,2,3,4,5,6].map(function(n){return '<option value="'+n+'"'+(String(d.pow_difficulty||'4')===String(n)?' selected':'')+'>'+n+' - '+['最简单','简单','中等','标准','困难','极难'][n-1]+'</option>';}).join('')+
                '</select><div class="unit">默认4（标准），范围1-6</div></div>'+
                '<div></div></div></div>'+
                '<div class="form-section"><h4><span class="dot"></span>验证码 &amp; 限流</h4><div class="form-grid-3">'+
                field('captcha_ttl','验证码有效期','分钟',(d.captcha||{}).ttl||5,'')+
                field('api_limit','API请求上限','次',(d.rate_limit||{}).api_limit||300,'窗口中最大请求数')+
                field('api_window','窗口','分钟',(d.rate_limit||{}).api_window||1,'限流统计窗口')+
                '</div></div>';
        case 'performance':
            return '<div class="form-section"><h4><span class="dot"></span>性能参数</h4><div class="form-grid-2">'+
                field('log_channel','日志通道缓冲','条',d.log_channel_size||10000,'异步写入缓冲队列')+
                field('cache_size','缓存大小','条',d.cache_size||1000,'内存缓存条目上限')+
                field('cache_ttl','缓存TTL','分钟',d.cache_ttl||5,'缓存数据过期时间')+
                field('max_body','请求体上限','MB',d.max_request_body||10,'超过此值返回413')+
                field('scan_buf','扫描缓冲','KB',Math.round((d.scan_buffer||1024)/1024),'检测器扫描缓冲区')+
                '<div class="fg"><label>上游压缩</label><select id="fld-disable_compression">'+
                '<option value="false"'+(!d.disable_compression?' selected':'')+'>启用 - 代理压缩响应</option>'+
                '<option value="true"'+(d.disable_compression?' selected':'')+'>禁用 - 透传原始响应</option>'+
                '</select><div class="unit">禁用后代理不再压缩上游响应</div></div>'+
                '</div></div>';
        case 'scheduler':
            return '<div class="form-section"><h4><span class="dot"></span>定时任务间隔</h4><div class="form-grid-2">'+
                field('health_check','健康检查','秒',d.health_check||5,'后端服务健康检查')+
                field('log_flush','日志刷盘','秒',d.log_flush||2,'缓冲日志写入文件')+
                field('log_cleanup','日志清理','小时',Math.round((d.log_cleanup||86400)/3600),'旧日志清理间隔')+
                field('metrics_cleanup','指标清理','分钟',d.metrics_cleanup||1,'指标数据清理')+
                field('rule_reload','规则重载','秒',d.rule_reload||5,'检测规则热加载')+
                '<div></div>'+
                '</div></div>';
        case 'websocket':
            return '<div class="form-section"><h4><span class="dot"></span>连接参数</h4><div class="form-grid-2">'+
                field('ws_push','仪表盘推送','秒',d.dashboard_push||2,'实时数据推送频率')+
                field('ws_heartbeat','心跳间隔','秒',d.log_heartbeat||30,'保活心跳间隔')+
                field('ws_buf','缓冲区','字节',d.buffer_size||1024,'消息缓冲大小')+
                field('ws_broadcast','广播通道','条',d.broadcast_channel||1000,'广播队列容量')+
                '</div></div>';
        case 'log':
            var retData = d.retention || {};
            return '<div class="form-section"><h4><span class="dot"></span>日志级别</h4><div class="form-grid-2">'+
                '<div class="fg"><label>日志级别</label><select id="fld-log_level">'+
                '<option value="debug"'+(d.level==='debug'?' selected':'')+'>Debug - 调试</option>'+
                '<option value="info"'+(d.level==='info'?' selected':'')+'>Info - 信息</option>'+
                '<option value="warn"'+(d.level==='warn'?' selected':'')+'>Warn - 警告</option>'+
                '<option value="error"'+(d.level==='error'?' selected':'')+'>Error - 错误</option>'+
                '</select><div class="unit">级别越低，输出越详细</div></div>'+
                '<div></div></div></div>'+
                '<div class="form-section"><h4><span class="dot"></span>日志轮转</h4><div class="form-grid-2">'+
                field('log_max_size','单文件上限','MB',d.max_size||100,'超过此大小自动轮转')+
                field('log_max_backups','保留文件数','个',d.max_backups||10,'旧日志文件最大数量')+
                field('log_max_age','保留天数','天',d.max_age||7,'超过此天数的日志自动删除')+
                '<div class="fg"><label>自动压缩</label><select id="fld-log_compress">'+
                '<option value="true"'+(d.compress?' selected':'')+'>是 - 节省磁盘</option>'+
                '<option value="false"'+(!d.compress?' selected':'')+'>否 - 保留原样</option>'+
                '</select><div class="unit">压缩旧轮转日志</div></div>'+
                '</div></div>'+
                '<div class="form-section"><h4><span class="dot"></span>日志字段</h4>'+
                '<p style="font-size:12px;color:#909399;margin-bottom:12px">控制访问日志中记录的请求字段，关闭可减少日志体积</p>'+
                '<div class="form-grid-2">'+
                chk('log_fld_host','记录Host',d.fields&&d.fields.host!==false?'checked':'','请求主机名')+
                chk('log_fld_query','记录Query',d.fields&&d.fields.query!==false?'checked':'','URL查询参数')+
                chk('log_fld_referer','记录Referer',d.fields&&d.fields.referer!==false?'checked':'','来源页面')+
                chk('log_fld_content_type','记录Content-Type',d.fields&&d.fields.content_type!==false?'checked':'','响应内容类型')+
                chk('log_fld_body_size','记录BodySize',d.fields&&d.fields.body_size!==false?'checked':'','响应体大小')+
                chk('log_fld_latency_us','记录微秒延迟',d.fields&&d.fields.latency_us?'checked':'','默认仅记录毫秒，开启后记录微秒级')+
                '</div></div>'+
                '<div class="form-section"><h4><span class="dot"></span>数据保留策略</h4><div class="form-grid-3">'+
                field('retention_log_days','访问日志','天',retData.log_retention_days||30,'超过此天数自动清理')+
                field('retention_metrics_days','指标数据','天',retData.metrics_retention_days||30,'超过此天数自动清理')+
                field('retention_admin_log_days','管理日志','天',retData.admin_log_retention_days||90,'超过此天数自动清理')+
                '</div></div>';
    }
    return '';
}

function field(id, label, unit, value, hint) {
    return '<div class="fg">' +
        '<label>' + label + '</label>' +
        '<input type="number" id="fld-' + id + '" value="' + value + '" min="0">' +
        (unit || hint ? '<div class="unit">' + (unit||'') + (hint?' &mdash; '+hint:'') + '</div>' : '') +
        '</div>';
}

function chk(id, label, checked, hint) {
    return '<div class="fg" style="display:flex;align-items:center;gap:8px">' +
        '<input type="checkbox" id="fld-' + id + '" ' + checked + ' style="width:16px;height:16px;flex-shrink:0">' +
        '<label for="fld-' + id + '" style="cursor:pointer">' + label + '</label>' +
        (hint ? '<span style="font-size:11px;color:#909399;margin-left:auto">' + hint + '</span>' : '') +
        '</div>';
}

function buildPasswordForm() {
    return '<div class="form-section"><h4><span class="dot"></span>修改管理员密码</h4>' +
        '<div style="display:flex;flex-direction:column;gap:14px">' +
        '<div class="fg"><label>当前密码</label><input type="password" id="current-pwd" placeholder="输入当前密码"></div>' +
        '<div class="fg"><label>新密码 <span style="color:#909399;font-weight:400">（至少6位）</span></label><input type="password" id="new-pwd" placeholder="输入新密码"></div>' +
        '<div class="fg"><label>确认新密码</label><input type="password" id="confirm-pwd" placeholder="再次输入新密码"></div>' +
        '</div></div>';
}

// ====== Trusted Proxy Modal ======
function buildProxyModal() {
    var proxies = (configData.proxy && configData.proxy.proxies) || [];
    var html = '<div class="form-section"><h4><span class="dot"></span>可信代理列表</h4>'+
        '<p style="font-size:12px;color:#909399;margin:0 0 12px;line-height:1.6">配置可信反向代理IP或CIDR。只有来自这些IP的 X-Forwarded-For / X-Real-IP 头信息才会被信任。留空则默认只信任本地回环地址(127.0.0.1/::1)。</p>'+
        '<div class="tag-list" id="proxy-tags">';
    proxies.forEach(function(p, i) {
        html += '<span class="tag-item">'+escapeHtml(p)+'<span class="tag-remove" onclick="removeProxy('+i+')">&times;</span></span>';
    });
    html += '</div>'+
        '<div class="tag-input-row">'+
        '<input type="text" id="proxy-input" placeholder="输入IP或CIDR，如 10.0.0.0/8 或 192.168.1.1" onkeydown="if(event.key===\'Enter\')addProxy()">'+
        '<button class="btn btn-primary btn-sm" onclick="addProxy()">添加</button>'+
        '</div></div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFoot').innerHTML =
        '<button class="btn btn-ghost" onclick="closeModal()">取消</button>' +
        '<button class="btn btn-submit" onclick="saveProxy()">&#128190; 保存配置</button>';
    document.getElementById('configModal').classList.add('show');
}

function addProxy() {
    var input = document.getElementById('proxy-input');
    var val = input.value.trim();
    if (!val) return;
    if (!configData.proxy.proxies) configData.proxy.proxies = [];
    if (configData.proxy.proxies.indexOf(val) >= 0) { showToast('error','该代理已存在'); return; }
    configData.proxy.proxies.push(val);
    input.value = '';
    buildProxyModal();
}

function removeProxy(idx) {
    if (configData.proxy.proxies) {
        configData.proxy.proxies.splice(idx, 1);
        buildProxyModal();
    }
}

function saveProxy() {
    var proxies = (configData.proxy && configData.proxy.proxies) || [];
    var btn = document.getElementById('configModal').querySelector('.btn-submit');
    btn.disabled = true; btn.textContent = '\u23F3 保存中...';
    fetch('/api/config/trusted-proxies', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify({proxies:proxies})})
        .then(function(r){return r.json()})
        .then(function(resp){
            if (resp.success) { showToast('success','可信代理配置已保存'); loadSection('proxy', function(){closeModal()}); btn.disabled=false; btn.textContent='\uD83D\uDCBE 保存配置'; }
            else { showToast('error', resp.error||'保存失败'); btn.disabled=false; btn.textContent='\uD83D\uDCBE 保存配置'; }
        }).catch(function(e){ showToast('error', e.message||'请求失败'); btn.disabled=false; btn.textContent='\uD83D\uDCBE 保存配置'; });
}

// ====== Admin Whitelist Modal ======
function buildWhitelistModal() {
    var cidrs = (configData.whitelist && configData.whitelist.cidrs) || [];
    var html = '<div class="form-section"><h4><span class="dot"></span>管理员IP白名单</h4>'+
        '<p style="font-size:12px;color:#909399;margin:0 0 12px;line-height:1.6">限制可访问管理后台的IP地址范围（CIDR格式）。留空则默认允许 127.0.0.1/8 和 ::1/128。保存后立即生效。</p>'+
        '<div class="tag-list" id="whitelist-tags">';
    cidrs.forEach(function(c, i) {
        html += '<span class="tag-item">'+escapeHtml(c)+'<span class="tag-remove" onclick="removeWhitelist('+i+')">&times;</span></span>';
    });
    html += '</div>'+
        '<div class="tag-input-row">'+
        '<input type="text" id="whitelist-input" placeholder="输入CIDR，如 10.0.0.0/8 或 192.168.1.0/24" onkeydown="if(event.key===\'Enter\')addWhitelist()">'+
        '<button class="btn btn-primary btn-sm" onclick="addWhitelist()">添加</button>'+
        '</div></div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFoot').innerHTML =
        '<button class="btn btn-ghost" onclick="closeModal()">取消</button>' +
        '<button class="btn btn-submit" onclick="saveWhitelist()">&#128190; 保存配置</button>';
    document.getElementById('configModal').classList.add('show');
}

function addWhitelist() {
    var input = document.getElementById('whitelist-input');
    var val = input.value.trim();
    if (!val) return;
    if (!configData.whitelist.cidrs) configData.whitelist.cidrs = [];
    if (configData.whitelist.cidrs.indexOf(val) >= 0) { showToast('error','该规则已存在'); return; }
    configData.whitelist.cidrs.push(val);
    input.value = '';
    buildWhitelistModal();
}

function removeWhitelist(idx) {
    if (configData.whitelist.cidrs) {
        configData.whitelist.cidrs.splice(idx, 1);
        buildWhitelistModal();
    }
}

function saveWhitelist() {
    var cidrs = (configData.whitelist && configData.whitelist.cidrs) || [];
    var btn = document.getElementById('configModal').querySelector('.btn-submit');
    btn.disabled = true; btn.textContent = '\u23F3 保存中...';
    fetch('/api/config/admin-whitelist', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify({cidrs:cidrs})})
        .then(function(r){return r.json()})
        .then(function(resp){
            if (resp.success) { showToast('success','IP白名单已保存，立即生效'); loadSection('whitelist', function(){closeModal()}); btn.disabled=false; btn.textContent='\uD83D\uDCBE 保存配置'; }
            else { showToast('error', resp.error||'保存失败'); btn.disabled=false; btn.textContent='\uD83D\uDCBE 保存配置'; }
        }).catch(function(e){ showToast('error', e.message||'请求失败'); btn.disabled=false; btn.textContent='\uD83D\uDCBE 保存配置'; });
}

// ====== API Key Modal ======
function buildApiKeyModal() {
    var html = '<div class="form-section"><h4><span class="dot"></span>API密钥管理</h4>'+
        '<p style="font-size:12px;color:#909399;margin:0 0 12px;line-height:1.6">管理WAF外部API访问密钥。密钥仅在创建时完整显示一次，请妥善保存。</p>'+
        '<div style="display:flex;gap:10px;margin-bottom:16px">'+
        '<input type="text" id="apikey-name" placeholder="输入密钥名称（如：监控系统集成）" style="flex:1;padding:8px 10px;border:1px solid #e4e7ed;border-radius:6px;font-size:13px">'+
        '<button class="btn btn-primary btn-sm" onclick="createApiKey()">创建密钥</button>'+
        '</div>'+
        '<div id="apikey-list">';
    if (apikeys.length === 0) {
        html += '<div class="apikey-empty">暂无API密钥，点击上方按钮创建</div>';
    } else {
        apikeys.forEach(function(k) {
            html += '<div class="apikey-row"><div class="apikey-info"><div class="apikey-name">'+escapeHtml(k.name)+'</div>'+
                '<div class="apikey-key">'+escapeHtml(k.key)+'</div>'+
                '<div class="apikey-date">创建于 '+formatDate(k.created_at)+'</div></div>'+
                '<div class="apikey-actions">'+
                '<label class="toggle-switch" title="'+(k.enabled?'已启用':'已禁用')+'"><input type="checkbox" '+(k.enabled?'checked':'')+' onchange="toggleApiKey(\''+k.id+'\',this.checked)"><span class="toggle-slider"></span></label>'+
                '<button class="btn btn-danger-o btn-sm" onclick="deleteApiKey(\''+k.id+'\',\''+escapeHtml(k.name)+'\')">删除</button></div></div>';
        });
    }
    html += '</div></div><div id="apikey-reveal"></div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFoot').innerHTML = '<button class="btn btn-ghost" onclick="closeModal()">关闭</button>';
    document.getElementById('configModal').classList.add('show');
}

function createApiKey() {
    var name = document.getElementById('apikey-name').value.trim();
    if (!name) { showToast('error','请输入密钥名称'); return; }
    fetch('/api/config/apikeys', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify({name:name})})
        .then(function(r){return r.json()})
        .then(function(resp){
            if (resp.success && resp.data) {
                showToast('success','密钥创建成功');
                document.getElementById('apikey-name').value = '';
                var reveal = document.getElementById('apikey-reveal');
                reveal.innerHTML = '<div class="key-reveal">新密钥: <b>'+escapeHtml(resp.data.key)+'</b><span class="key-copy-btn" onclick="copyKey(this)" data-key="'+escapeHtml(resp.data.key)+'">复制</span><br><span style="color:#f56c6c;font-size:11px">请立即保存此密钥，关闭后无法再次查看完整密钥</span></div>';
                fetch('/api/config/apikeys').then(function(r2){return r2.json()}).then(function(resp2){
                    apikeys = (resp2.data && resp2.data.keys) || [];
                    updateSummary('apikey', {});
                });
            } else {
                showToast('error', resp.error || '创建失败');
            }
        }).catch(function(e){ showToast('error', e.message||'请求失败'); });
}

function toggleApiKey(id, enabled) {
    fetch('/api/config/apikeys/toggle', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify({id:id, enabled:enabled})})
        .then(function(r){return r.json()})
        .then(function(resp){
            if (resp.success) { showToast('success', enabled?'密钥已启用':'密钥已禁用'); }
            else { showToast('error', resp.error||'操作失败'); }
        }).catch(function(e){ showToast('error', e.message||'请求失败'); });
}

function deleteApiKey(id, name) {
    if (!confirm('确定要删除密钥 "'+name+'" 吗？此操作不可恢复。')) return;
    fetch('/api/config/apikeys/delete', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify({id:id})})
        .then(function(r){return r.json()})
        .then(function(resp){
            if (resp.success) { showToast('success','密钥已删除'); buildApiKeyModal(); }
            else { showToast('error', resp.error||'删除失败'); }
        }).catch(function(e){ showToast('error', e.message||'请求失败'); });
}

function copyKey(el) {
    var key = el.getAttribute('data-key');
    navigator.clipboard.writeText(key).then(function(){ showToast('success','已复制到剪贴板'); });
}

function formatDate(ts) {
    if (!ts) return '';
    var d = new Date(ts * 1000);
    return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0')+' '+String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');
}

function closeModal() {
    document.getElementById('configModal').classList.remove('show');
    currentSection = '';
}

function changePassword() {
    var cur = document.getElementById('current-pwd').value;
    var neu = document.getElementById('new-pwd').value;
    var con = document.getElementById('confirm-pwd').value;
    if (!cur) { showToast('error','请输入当前密码'); return; }
    if (neu.length < 6) { showToast('error','新密码至少6位'); return; }
    if (neu !== con) { showToast('error','两次密码不一致'); return; }
    fetch('/api/admin/change-password', {
        method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()},
        body:JSON.stringify({old_password:cur, new_password:neu})
    }).then(r => r.json()).then(function(resp) {
        if (resp.success) { showToast('success','密码已修改'); closeModal(); }
        else showToast('error', resp.error || '修改失败');
    }).catch(function(){showToast('error','请求失败');});
}

function collectData(section) {
    function v(id) { return parseInt(document.getElementById('fld-' + id).value) || 0; }
    function sv(id) { var el = document.getElementById('fld-' + id); return el ? el.value : ''; }
    switch(section) {
        case 'security':
            var d = {login:{max_attempts:v('login_max_attempts'),block_duration:v('login_block_duration')},
                session:{ttl:v('session_ttl'),cleanup_interval:v('session_cleanup')},
                captcha:{ttl:v('captcha_ttl')}, rate_limit:{api_limit:v('api_limit'),api_window:v('api_window')},
                session_safe:{ip_mutation_threshold:v('sessionsafe_ip_threshold'),ua_detection_enabled:sv('sessionsafe_ua_enabled')==='true'},
                pow_difficulty:v('pow_difficulty')};
            if (d.login.max_attempts < 1) { showToast('error','尝试次数至少为1'); return null; }
            return d;
        case 'performance':
            return {log_channel_size:v('log_channel'),cache_size:v('cache_size'),cache_ttl:v('cache_ttl'),
                max_request_body:v('max_body'),scan_buffer:v('scan_buf')*1024,
                disable_compression:sv('disable_compression')==='true'};
        case 'scheduler':
            return {health_check:v('health_check'),log_flush:v('log_flush'),log_cleanup:v('log_cleanup')*3600,
                metrics_cleanup:v('metrics_cleanup'),rule_reload:v('rule_reload')};
        case 'websocket':
            return {dashboard_push:v('ws_push'),log_heartbeat:v('ws_heartbeat'),buffer_size:v('ws_buf'),
                broadcast_channel:v('ws_broadcast')};
        case 'log':
            return {level:sv('log_level'),max_size:v('log_max_size'),max_backups:v('log_max_backups'),
                max_age:v('log_max_age'),compress:sv('log_compress')==='true',
                fields:{host:!!document.getElementById('fld-log_fld_host').checked,
                    query:!!document.getElementById('fld-log_fld_query').checked,
                    referer:!!document.getElementById('fld-log_fld_referer').checked,
                    content_type:!!document.getElementById('fld-log_fld_content_type').checked,
                    body_size:!!document.getElementById('fld-log_fld_body_size').checked,
                    latency_us:!!document.getElementById('fld-log_fld_latency_us').checked},
                retention:{log_retention_days:v('retention_log_days'),metrics_retention_days:v('retention_metrics_days'),
                    admin_log_retention_days:v('retention_admin_log_days')}};
    }
    return null;
}

// ====== Backup/Restore Modal ======
function buildBackupModal() {
    var html = '<div class="form-section"><h4><span class="dot"></span>配置备份</h4>'+
        '<p style="font-size:12px;color:#909399;margin:0 0 16px;line-height:1.6">将全部配置（域名、后端、规则、系统设置等）导出为JSON文件，可用于迁移或灾难恢复。</p>'+
        '<button class="btn btn-primary" onclick="downloadBackup()">&#128229; 下载备份文件</button>'+
        '</div>'+
        '<div class="form-section"><h4><span class="dot"></span>配置还原</h4>'+
        '<p style="font-size:12px;color:#909399;margin:0 0 12px;line-height:1.6">上传之前导出的JSON备份文件进行还原。<b style="color:#f56c6c">警告：还原将覆盖当前全部配置。</b></p>'+
        '<input type="file" id="restore-file" accept=".json" style="margin-bottom:10px">'+
        '<button class="btn btn-danger" onclick="restoreBackup()">&#8617; 还原配置</button>'+
        '</div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFoot').innerHTML = '<button class="btn btn-ghost" onclick="closeModal()">关闭</button>';
    document.getElementById('configModal').classList.add('show');
}

function downloadBackup() {
    window.location.href = '/api/config/backup';
    showToast('success','正在下载备份文件...');
}

function restoreBackup() {
    var fileInput = document.getElementById('restore-file');
    if (!fileInput.files || !fileInput.files[0]) { showToast('error','请先选择备份文件'); return; }
    if (!confirm('确定要还原配置吗？当前所有配置将被替换，此操作不可撤销！')) return;
    var reader = new FileReader();
    reader.onload = function() {
        try {
            var raw = JSON.parse(reader.result);
            // 兼容两种格式：直接导出的备份文件 或 从API响应提取的data字段
            var backup = raw.configs ? raw : (raw.data ? raw.data : raw);
            if (!backup.configs) { showToast('error','文件格式错误：缺少configs字段'); return; }
            fetch('/api/config/restore', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify(backup)})
                .then(function(r){return r.json()})
                .then(function(resp){
                    if (resp.success) { showToast('success','配置已还原，请重启服务使其生效'); closeModal(); }
                    else showToast('error', resp.error || '还原失败');
                }).catch(function(e){showToast('error', e.message||'请求失败');});
        } catch(e) { showToast('error','文件格式错误，请选择有效的JSON备份文件'); }
    };
    reader.readAsText(fileInput.files[0]);
}

// ====== GeoIP Update Modal ======
function buildGeoIPModal() {
    var d = configData.geoip || {};
    var html = '<div class="form-section"><h4><span class="dot"></span>GeoIP数据库更新</h4>'+
        '<div class="form-grid-2">'+
        '<div class="fg"><label>当前数据库</label><div style="padding:8px 0;font-size:13px;">'+(d.last_update_time ? formatDate(d.last_update_time) : '<em style="color:#f56c6c">未更新</em>')+'</div></div>'+
        '<div class="fg"><label>数据库路径</label><div style="padding:8px 0;font-size:12px;color:#909399;word-break:break-all;">'+(d.db_path||'GeoLite2-City.mmdb')+'</div></div>'+
        '</div>'+
        '<div class="form-grid-2">'+
        '<div class="fg"><label>上传更新</label>'+
        '<input type="file" id="geoip-file" accept=".mmdb" style="padding:6px 0;font-size:13px;max-width:100%;" onchange="onGeoIPFileSelected(this)">'+
        '<div id="geoip-file-info" style="font-size:12px;color:#909399;margin-top:4px;"></div>'+
        '</div>'+
        '</div>'+
        '<div style="margin-top:12px;display:flex;gap:8px"><button class="btn btn-primary btn-sm" id="geoip-upload-btn" onclick="uploadGeoIPFile(this)" disabled>&#128228; 上传并更新</button>'+
        '<button class="btn btn-ghost btn-sm" onclick="showToast(\'info\',\'选择.mmdb文件上传替换当前GeoIP数据库\')">&#63;</button>'+
        '</div></div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFoot').innerHTML =
        '<button class="btn btn-ghost" onclick="closeModal()">取消</button>';
    document.getElementById('configModal').classList.add('show');
}

function onGeoIPFileSelected(input) {
    var btn = document.getElementById('geoip-upload-btn');
    var info = document.getElementById('geoip-file-info');
    if (!input.files || !input.files.length) {
        if (btn) btn.disabled = true;
        if (info) info.textContent = '';
        return;
    }
    var file = input.files[0];
    if (!file.name.endsWith('.mmdb')) {
        showToast('error', '请选择 .mmdb 格式的 GeoIP 数据库文件');
        if (btn) btn.disabled = true;
        if (info) info.textContent = '';
        input.value = '';
        return;
    }
    var sizeMB = (file.size / 1024 / 1024).toFixed(1);
    if (info) info.textContent = file.name + ' (' + sizeMB + ' MB)';
    if (btn) btn.disabled = false;
}

function uploadGeoIPFile(btn) {
    var fileInput = document.getElementById('geoip-file');
    if (!fileInput || !fileInput.files || !fileInput.files.length) {
        showToast('error', '请先选择 .mmdb 文件');
        return;
    }
    var file = fileInput.files[0];
    btn.disabled = true; btn.textContent = '\u23F3 上传中...';
    var formData = new FormData();
    formData.append('file', file);
    var csrfToken = getCSRFToken();
    fetch('/api/geoip/upload', {
        method: 'POST',
        headers: csrfToken ? {'X-CSRF-Token': csrfToken} : {},
        body: formData
    })
    .then(function(r){ return r.json(); })
    .then(function(resp){
        if (resp.success) {
            showToast('success', 'GeoIP数据库上传并更新成功');
            loadSection('geoip', function(){ closeModal(); });
        } else {
            showToast('error', resp.error || '上传失败');
            btn.disabled = false; btn.textContent = '\uD83D\uDCE4 上传并更新';
        }
    })
    .catch(function(e){
        showToast('error', '上传失败: ' + (e.message||''));
        btn.disabled = false; btn.textContent = '\uD83D\uDCE4 上传并更新';
    });
}

// ====== Global Switch Modal ======
function buildGlobalModal() {
    var enabled = (configData.global && configData.global.enabled);
    var html = '<div class="form-section"><h4><span class="dot"></span>WAF 全局总开关</h4>'+
        '<p style="font-size:12px;color:#909399;margin:0 0 16px;line-height:1.6">关闭后所有WAF检测（攻击检测、限流、Bot管理等）将停止工作，所有请求直接透传到后端。适用于护网、压测等场景。</p>'+
        '<div style="text-align:center;padding:20px 0">'+
        '<div style="font-size:48px;margin-bottom:10px">'+(enabled?'&#128994;':'&#128308;')+'</div>'+
        '<div style="font-size:18px;font-weight:600;color:'+(enabled?'#52c41a':'#f56c6c')+'">'+(enabled?'WAF 运行中':'WAF 已暂停')+'</div>'+
        '<div style="margin-top:10px"><button class="btn '+(enabled?'btn-danger':'btn-primary')+'" onclick="toggleGlobal()">'+(enabled?'&#9208; 暂停 WAF':'&#9654; 启动 WAF')+'</button></div>'+
        '</div></div>';
    document.getElementById('modalBody').innerHTML = html;
    document.getElementById('modalFoot').innerHTML = '<button class="btn btn-ghost" onclick="closeModal()">关闭</button>';
    document.getElementById('configModal').classList.add('show');
}

function toggleGlobal() {
    var cur = (configData.global && configData.global.enabled);
    var want = !cur;
    var msg = want ? '确定要启动WAF吗？' : '确定要暂停WAF吗？所有安全防护将不可用。';
    if (!confirm(msg)) return;
    fetch('/api/config/global-enabled', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}, body:JSON.stringify({enabled:want})})
        .then(function(r){return r.json()})
        .then(function(resp){
            if (resp.success) {
                configData.global = {enabled: want};
                updateSummary('global', configData.global);
                showToast('success', want?'WAF已启动':'WAF已暂停');
                buildGlobalModal();
            } else showToast('error', resp.error||'操作失败');
        }).catch(function(e){showToast('error', e.message||'请求失败');});
}

function resetCurrent() {
    if (!currentSection || !SECTION[currentSection] || !SECTION[currentSection].reset) return;
    if (!confirm('确定要恢复默认配置吗？此操作不可撤销。')) return;
    var url = SECTION[currentSection].reset;
    fetch(url, {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': getCSRFToken()}})
        .then(function(r){return r.json()})
        .then(function(resp){
            if (resp.success) {
                showToast('success','已恢复默认配置');
                loadSection(currentSection, function(){ closeModal(); });
            } else {
                showToast('error', resp.error || '恢复失败');
            }
        }).catch(function(e){ showToast('error', e.message || '请求失败'); });
}

loadAll();

// Section filtering: hash-based card visibility
var sectionNames = {
    security: '安全与性能',
    log: '日志与数据',
    proxy: '代理与白名单',
    apikey: '密钥与工具'
};
var breadcrumb = document.getElementById('sectionBreadcrumb');
var sectionLabel = document.getElementById('sectionLabel');
var grid = document.getElementById('configGrid');
var subtitle = document.querySelector('.main > p');

function filterBySection(section) {
    var cards = grid.querySelectorAll('.config-card[data-section]');
    if (!section || !sectionNames[section]) {
        cards.forEach(function(c) { c.style.display = ''; });
        if (breadcrumb) breadcrumb.style.display = 'none';
        if (subtitle) subtitle.textContent = 'GoWAF 运行参数集中管理，点击卡片打开设置弹窗';
        return;
    }
    cards.forEach(function(c) {
        c.style.display = c.getAttribute('data-section') === section ? '' : 'none';
    });
    if (breadcrumb) breadcrumb.style.display = '';
    if (sectionLabel) sectionLabel.textContent = sectionNames[section];
    if (subtitle) subtitle.textContent = '当前分类: ' + sectionNames[section];
}

function handleHashFilter() {
    var hash = (window.location.hash || '').replace('#', '');
    filterBySection(hash);
}
setTimeout(handleHashFilter, 100);
window.addEventListener('hashchange', handleHashFilter);
