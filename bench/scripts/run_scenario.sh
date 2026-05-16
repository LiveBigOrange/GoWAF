#!/bin/bash
# 单独运行指定场景
# 用法: bash run_scenario.sh <场景号> [TARGET_URL]
# 示例: bash run_scenario.sh 1 http://192.168.1.100:80

if [ -z "$1" ]; then
  echo "用法: bash run_scenario.sh <场景号> [TARGET_URL]"
  echo ""
  echo "可用场景:"
  echo "  1 - 干净流量吞吐量（基准线）"
  echo "  2 - 恶意流量检测（CPU 压力）"
  echo "  3 - 高并发连接（内存压力）"
  echo "  4 - 大量唯一IP（限流器 + 画像）"
  echo "  5 - 大请求体 + 大响应体（I/O + 内存）"
  echo "  6 - 混合流量（真实场景模拟）"
  echo "  7 - 长时间稳定性（耐久测试）"
  echo "  8 - 特殊攻击模式"
  echo ""
  echo "示例: bash run_scenario.sh 2 http://192.168.1.100:80"
  exit 1
fi

SCENARIO=$1
TARGET="${2:-http://127.0.0.1:80}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

export TARGET

case $SCENARIO in
  1) bash "${SCRIPT_DIR}/s1_clean_traffic.sh" ;;
  2) bash "${SCRIPT_DIR}/s2_malicious_traffic.sh" ;;
  3) bash "${SCRIPT_DIR}/s3_high_concurrency.sh" ;;
  4) bash "${SCRIPT_DIR}/s4_multi_ip.sh" ;;
  5) bash "${SCRIPT_DIR}/s5_large_payload.sh" ;;
  6) bash "${SCRIPT_DIR}/s6_realistic_mix.sh" ;;
  7) bash "${SCRIPT_DIR}/s7_endurance.sh" ;;
  8) bash "${SCRIPT_DIR}/s8_special_attacks.sh" ;;
  *) echo "未知场景: $SCENARIO"; exit 1 ;;
esac
