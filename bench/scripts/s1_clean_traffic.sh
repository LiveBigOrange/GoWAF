TARGET="http://127.0.0.1:80"
THREADS_LOW=2
THREADS_HIGH=4
DURATION="30s"
RESULTS_DIR="$(dirname "$0")/results"
mkdir -p "$RESULTS_DIR"

echo "=========================================="
echo "  场景1: 干净流量吞吐量（基准线）"
echo "  目标: ${TARGET}"
echo "=========================================="

run_bench() {
  label=$1
  shift
  outfile="${RESULTS_DIR}/s1_clean_${label}.txt"
  echo ""
  echo "--- ${label} ---"
  wrk "$@" -d "$DURATION" --latency "$TARGET" 2>&1 | tee "$outfile"
}

run_bench "c100"  -t$THREADS_LOW  -c100
run_bench "c200"  -t$THREADS_LOW  -c200
run_bench "c500"  -t$THREADS_HIGH -c500
run_bench "c1000" -t$THREADS_HIGH -c1000
run_bench "c2000" -t$THREADS_HIGH -c2000
run_bench "c5000" -t$THREADS_HIGH -c5000

echo ""
echo "=========================================="
echo "  场景1.1: 多路径干净流量"
echo "=========================================="
wrk -t$THREADS_HIGH -c500 -d60s --latency \
  -s "$(dirname "$0")/lua/clean_traffic.lua" \
  "$TARGET" 2>&1 | tee "${RESULTS_DIR}/s1_clean_multipath.txt"
