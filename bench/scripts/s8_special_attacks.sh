TARGET="http://127.0.0.1:80"
LUA_DIR="$(dirname "$0")/lua"
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景8: 特殊攻击模式（限流器 + 规则引擎）"
echo "  目标: ${TARGET}"
echo "=========================================="

# --- 8.1 高频同 IP 请求（触发限流）---
echo ""
echo "--- 8.1 高频同 IP 请求（触发简单限流器）---"
for c in 100 500 1000; do
  echo "  并发: $c"
  wrk -t4 -c${c} -d30s --latency \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s8_1_ratelimit_c${c}.txt"
done

# --- 8.2 模拟扫描器行为 ---
echo ""
echo "--- 8.2 模拟扫描器行为 ---"
for c in 50 100 200; do
  echo "  并发: $c"
  wrk -t2 -c${c} -d30s --latency \
    -s "${LUA_DIR}/scanner_sim.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s8_2_scanner_c${c}.txt"
done

# --- 8.3 慢速请求（Slowloris 风格，wrk 模拟有限）---
echo ""
echo "--- 8.3 持续慢速请求 ---"
wrk -t1 -c100 -d60s --latency \
  -H "Connection: keep-alive" \
  -s "${LUA_DIR}/clean_traffic.lua" \
  "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s8_3_slow_requests.txt"

# --- 8.4 HTTP 方法枚举 ---
echo ""
echo "--- 8.4 HTTP 方法枚举 ---"
cat > "${LUA_DIR}/method_enum.lua" << 'LUAEOF'
local counter = 0
local methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "PROPFIND", "SEARCH"}

request = function()
  counter = counter + 1
  local method = methods[(counter % #methods) + 1]
  return wrk.format(method, "/api/data", {
    ["User-Agent"] = "Mozilla/5.0",
    ["Content-Type"] = "application/json"
  }, '{}')
end
LUAEOF

wrk -t2 -c100 -d30s --latency \
  -s "${LUA_DIR}/method_enum.lua" \
  "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s8_4_method_enum.txt"
