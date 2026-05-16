TARGET="http://127.0.0.1:80"
LUA_DIR="$(dirname "$0")/lua"
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景3: 高并发连接（内存压力）"
echo "  目标: ${TARGET}"
echo "=========================================="

# --- 3.1 Keep-Alive 长连接 ---
echo ""
echo "--- 3.1 Keep-Alive 长连接压力 ---"
for c in 1000 3000 5000 10000; do
  echo "  并发连接: $c"
  wrk -t4 -c${c} -d60s --latency \
    -H "Connection: keep-alive" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s3_1_keepalive_c${c}.txt"
  echo "  等待 10s 让 WAF 释放资源..."
  sleep 10
done

# --- 3.2 短连接风暴 ---
echo ""
echo "--- 3.2 短连接风暴 ---"
for c in 200 500 1000; do
  echo "  并发: $c"
  wrk -t4 -c${c} -d30s --latency \
    -s "${LUA_DIR}/short_conn.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s3_2_shortconn_c${c}.txt"
  echo "  等待 10s..."
  sleep 10
done
