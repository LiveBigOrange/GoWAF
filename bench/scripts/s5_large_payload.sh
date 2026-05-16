TARGET="http://127.0.0.1:80"
LUA_DIR="$(dirname "$0")/lua"
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景5: 大请求体 + 大响应体（I/O + 内存）"
echo "  目标: ${TARGET}"
echo "  前提: 后端需支持 POST /api/upload 和返回大响应"
echo "=========================================="

# --- 5.1 大请求体 POST ---
echo ""
echo "--- 5.1 大请求体 POST ---"
for c in 50 100 200; do
  echo "  并发: $c"
  wrk -t2 -c${c} -d30s --latency \
    -s "${LUA_DIR}/large_body.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s5_1_large_body_c${c}.txt"
  echo "  等待 10s..."
  sleep 10
done

# --- 5.2 混合方法请求 ---
echo ""
echo "--- 5.2 混合方法请求（GET/HEAD/OPTIONS）---"
for c in 200 500 1000; do
  echo "  并发: $c"
  wrk -t4 -c${c} -d30s --latency \
    -s "${LUA_DIR}/mixed_methods.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s5_2_mixed_methods_c${c}.txt"
done
