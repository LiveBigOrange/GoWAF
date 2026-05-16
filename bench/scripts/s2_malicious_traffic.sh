TARGET="http://127.0.0.1:80"
LUA_DIR="$(dirname "$0")/lua"
RESULTS_DIR="$(dirname "$0")/results"
DURATION="30s"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景2: 恶意流量检测（CPU 压力）"
echo "  目标: ${TARGET}"
echo "=========================================="

# --- 2.1 SQL 注入 ---
echo ""
echo "--- 2.1 SQL 注入检测 ---"
for c in 100 200 500; do
  t=2; [ "$c" -ge 500 ] && t=4
  echo "  并发: $c"
  wrk -t${t} -c${c} -d"$DURATION" --latency \
    -s "${LUA_DIR}/sqli_attack.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s2_1_sqli_c${c}.txt"
done

# --- 2.2 XSS ---
echo ""
echo "--- 2.2 XSS 检测 ---"
for c in 100 200; do
  echo "  并发: $c"
  wrk -t2 -c${c} -d"$DURATION" --latency \
    -s "${LUA_DIR}/xss_attack.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s2_2_xss_c${c}.txt"
done

# --- 2.3 命令注入 ---
echo ""
echo "--- 2.3 命令注入检测 ---"
wrk -t2 -c100 -d"$DURATION" --latency \
  -s "${LUA_DIR}/cmdi_attack.lua" \
  "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s2_3_cmdi_c100.txt"

# --- 2.4 路径遍历 ---
echo ""
echo "--- 2.4 路径遍历检测 ---"
wrk -t2 -c100 -d"$DURATION" --latency \
  -s "${LUA_DIR}/path_traversal_attack.lua" \
  "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s2_4_pathtraversal_c100.txt"

# --- 2.5 混合攻击 ---
echo ""
echo "--- 2.5 混合攻击 ---"
for c in 50 100 200 500; do
  t=2; [ "$c" -ge 500 ] && t=4
  echo "  并发: $c"
  wrk -t${t} -c${c} -d"$DURATION" --latency \
    -s "${LUA_DIR}/mixed_attack.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s2_5_mixed_c${c}.txt"
done

# --- 2.6 POST 恶意请求体 ---
echo ""
echo "--- 2.6 POST 恶意请求体 ---"
for c in 100 200; do
  echo "  并发: $c"
  wrk -t2 -c${c} -d"$DURATION" --latency \
    -s "${LUA_DIR}/post_attack.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s2_6_post_c${c}.txt"
done
