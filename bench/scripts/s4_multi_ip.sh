TARGET="http://127.0.0.1:80"
LUA_DIR="$(dirname "$0")/lua"
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景4: 大量唯一 IP（限流器 + 画像内存）"
echo "  目标: ${TARGET}"
echo "  注意: 需要确认 WAF 读取 X-Forwarded-For 头"
echo "=========================================="

# --- 4.1 唯一 IP + 正常请求 ---
echo ""
echo "--- 4.1 唯一 IP 正常请求（测试 IP 限流器内存）---"
for c in 100 500 1000; do
  echo "  并发: $c"
  wrk -t4 -c${c} -d60s --latency \
    -s "${LUA_DIR}/multi_ip.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s4_1_multiip_c${c}.txt"
  echo "  等待 10s..."
  sleep 10
done

# --- 4.2 唯一 IP + 攻击请求（测试画像系统压力）---
echo ""
echo "--- 4.2 唯一 IP 攻击请求（测试智能画像系统）---"
for c in 100 500 1000; do
  echo "  并发: $c"
  wrk -t4 -c${c} -d60s --latency \
    -s "${LUA_DIR}/multi_ip_attack.lua" \
    "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s4_2_multiip_attack_c${c}.txt"
  echo "  等待 10s..."
  sleep 10
done

echo ""
echo "注意: 测试结束后检查 WAF 内存占用，观察是否释放"
