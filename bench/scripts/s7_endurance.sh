TARGET="http://127.0.0.1:80"
LUA_DIR="$(dirname "$0")/lua"
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景7: 长时间稳定性（耐久测试）"
echo "  目标: ${TARGET}"
echo "  持续运行 1 小时，监控内存/Goroutine 泄漏"
echo "=========================================="

# --- 7.1 稳定负载 1 小时 ---
echo ""
echo "--- 7.1 稳定负载 (200 并发, 1小时) ---"
echo "  开始时间: $(date)"
wrk -t4 -c200 -d3600s --latency \
  -s "${LUA_DIR}/realistic_mix.lua" \
  "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s7_1_endurance_1h.txt"

# --- 7.2 间歇性压力（模拟流量波峰波谷）---
echo ""
echo "--- 7.2 间歇性压力（10轮，每轮5分钟）---"
for round in $(seq 1 10); do
  echo ""
  echo "=== 第 ${round}/10 轮 ==="
  echo "  开始时间: $(date)"

  # 高峰期 200 并发
  echo "  --- 高峰期 (200 并发, 3分钟) ---"
  wrk -t4 -c200 -d180s --latency \
    -s "${LUA_DIR}/mixed_attack.lua" \
    "$TARGET" 2>&1 | tee -a "${RESULTS_DIR}/s7_2_intermittent.txt"

  # 低谷期 50 并发
  echo "  --- 低谷期 (50 并发, 2分钟) ---"
  wrk -t2 -c50 -d120s --latency \
    -s "${LUA_DIR}/clean_traffic.lua" \
    "$TARGET" 2>&1 | tee -a "${RESULTS_DIR}/s7_2_intermittent.txt"
done

echo ""
echo "稳定性测试完成: $(date)"
