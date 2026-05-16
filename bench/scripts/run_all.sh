#!/bin/bash
# 一键运行所有压测场景
# 用法: bash run_all.sh [TARGET_URL]
# 示例: bash run_all.sh http://192.168.1.100:80

set -e

TARGET="${1:-http://127.0.0.1:80}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

export TARGET

echo "============================================================"
echo "  GoWAF 压测套件 - 一键运行"
echo "  目标: ${TARGET}"
echo "  结果目录: ${RESULTS_DIR}"
echo "  开始时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo ""

# 检查 wrk 是否安装
if ! command -v wrk &>/dev/null; then
  echo "错误: wrk 未安装"
  echo "安装: git clone https://github.com/wg/wrk && cd wrk && make && sudo cp wrk /usr/local/bin/"
  exit 1
fi

mkdir -p "$RESULTS_DIR"

# 全局摘要文件
SUMMARY="${RESULTS_DIR}/summary_$(date +%Y%m%d_%H%M%S).txt"
echo "GoWAF 压测报告" > "$SUMMARY"
echo "目标: ${TARGET}" >> "$SUMMARY"
echo "时间: $(date '+%Y-%m-%d %H:%M:%S')" >> "$SUMMARY"
echo "============================================" >> "$SUMMARY"

run_scenario() {
  local num=$1
  local name=$2
  local script=$3

  echo ""
  echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "  场景${num}: ${name}"
  echo "  开始: $(date '+%H:%M:%S')"
  echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
  echo ""

  echo "" >> "$SUMMARY"
  echo "场景${num}: ${name}" >> "$SUMMARY"
  echo "开始: $(date '+%H:%M:%S')" >> "$SUMMARY"
  echo "---" >> "$SUMMARY"

  bash "$script"

  echo "---" >> "$SUMMARY"
  echo "结束: $(date '+%H:%M:%S')" >> "$SUMMARY"
}

# 替换脚本中的 TARGET
export TARGET

# 运行所有场景
run_scenario 1 "干净流量吞吐量" "${SCRIPT_DIR}/s1_clean_traffic.sh"
run_scenario 2 "恶意流量检测"   "${SCRIPT_DIR}/s2_malicious_traffic.sh"
run_scenario 3 "高并发连接"     "${SCRIPT_DIR}/s3_high_concurrency.sh"
run_scenario 4 "大量唯一IP"     "${SCRIPT_DIR}/s4_multi_ip.sh"
run_scenario 5 "大请求体"       "${SCRIPT_DIR}/s5_large_payload.sh"
run_scenario 6 "混合流量"       "${SCRIPT_DIR}/s6_realistic_mix.sh"
run_scenario 7 "长时间稳定性"   "${SCRIPT_DIR}/s7_endurance.sh"
run_scenario 8 "特殊攻击模式"   "${SCRIPT_DIR}/s8_special_attacks.sh"

echo ""
echo "============================================================"
echo "  所有压测场景已完成!"
echo "  结束时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "  结果目录: ${RESULTS_DIR}"
echo "  摘要文件: ${SUMMARY}"
echo "============================================================"
