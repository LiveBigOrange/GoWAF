TARGET="http://127.0.0.1:80"
LUA_DIR="$(dirname "$0")/lua"
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景6: 混合流量（真实场景模拟）"
echo "  目标: ${TARGET}"
echo "  比例: 80% 正常 + 15% 扫描 + 5% 攻击"
echo "=========================================="

cat > "${LUA_DIR}/realistic_mix.lua" << 'LUAEOF'
local counter = 0

local normal_paths = {
  "/", "/index.html", "/api/users?page=1",
  "/api/products?category=electronics",
  "/static/css/main.css", "/static/js/app.js",
  "/images/logo.png", "/favicon.ico", "/health",
  "/about", "/contact", "/api/data?limit=20"
}

local scan_paths = {
  "/admin", "/.env", "/wp-admin/",
  "/phpmyadmin/", "/actuator/health",
  "/debug/", "/server-status", "/.git/config"
}

local attack_paths = {
  "/api/login?user=admin' OR 1=1--",
  "/search?q=<script>alert(1)</script>",
  "/api/ping?host=;cat /etc/passwd",
  "/files/../../../etc/passwd"
}

request = function()
  counter = counter + 1
  local roll = counter % 100

  if roll < 80 then
    local path = normal_paths[(counter % #normal_paths) + 1]
    return wrk.format("GET", path, {
      ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      ["Accept"] = "text/html,application/xhtml+xml",
      ["Accept-Language"] = "zh-CN,zh;q=0.9",
      ["Connection"] = "keep-alive"
    })
  elseif roll < 95 then
    local path = scan_paths[(counter % #scan_paths) + 1]
    return wrk.format("GET", path, {
      ["User-Agent"] = "DirBuster/1.0",
      ["Accept"] = "*/*"
    })
  else
    local path = attack_paths[(counter % #attack_paths) + 1]
    return wrk.format("GET", path, {
      ["User-Agent"] = "Mozilla/5.0",
      ["Accept"] = "*/*"
    })
  end
end
LUAEOF

# 阶梯加压
for c in 100 200 500 1000; do
  t=2; [ "$c" -ge 500 ] && t=4
  echo ""
  echo "--- 并发: $c ---"
  wrk -t${t} -c${c} -d60s --latency \
    -s "${LUA_DIR}/realistic_mix.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s6_realistic_c${c}.txt"
done
