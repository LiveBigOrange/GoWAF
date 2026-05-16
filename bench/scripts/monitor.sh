#!/bin/bash
# WAF 服务端资源监控脚本
# 在 WAF 服务器上运行: bash monitor.sh [间隔秒数] [输出文件]
# 用法: bash monitor.sh 2 /tmp/waf_monitor.log

INTERVAL=${1:-2}
OUTFILE=${2:-""}
PID=$(pgrep -f 'cmd/waf' | head -1)

if [ -z "$PID" ]; then
  echo "错误: 未找到 WAF 进程 (cmd/waf)"
  echo "请先启动 WAF 服务"
  exit 1
fi

echo "监控 WAF 进程 PID: $PID, 间隔: ${INTERVAL}s"
if [ -n "$OUTFILE" ]; then
  echo "输出到: $OUTFILE"
fi
echo "按 Ctrl+C 停止"
echo ""

header="时间 | CPU% | 内存RSS(MB) | 内存占比% | Goroutines | FD数 | TCP连接 | 线程数"
echo "$header"
if [ -n "$OUTFILE" ]; then echo "$header" > "$OUTFILE"; fi

while true; do
  ts=$(date +%H:%M:%S)

  cpu=$(top -bn1 -p "$PID" 2>/dev/null | awk -v pid="$PID" '$1==pid {print $9}' | head -1)
  [ -z "$cpu" ] && cpu="0.0"

  mem_kb=$(grep VmRSS /proc/$PID/status 2>/dev/null | awk '{print $2}')
  [ -z "$mem_kb" ] && mem_kb=0
  mem_mb=$(echo "scale=1; $mem_kb/1024" | bc 2>/dev/null || echo "0")

  total_mem=$(free -m | awk '/^Mem:/{print $2}')
  mem_pct=$(echo "scale=1; $mem_kb*100*1024/($total_mem*1024*1024)" | bc 2>/dev/null || echo "0.0")

  goroutines=$(curl -sf http://127.0.0.1:8080/api/stats 2>/dev/null \
    | grep -o '"goroutines":[0-9]*' | cut -d: -f2)
  [ -z "$goroutines" ] && goroutines="N/A"

  fd_count=$(ls /proc/$PID/fd 2>/dev/null | wc -l)
  [ -z "$fd_count" ] && fd_count="N/A"

  tcp_conns=$(ss -tnp 2>/dev/null | grep "pid=$PID" | grep -c ESTAB)
  [ -z "$tcp_conns" ] && tcp_conns="0"

  threads=$(grep Threads /proc/$PID/status 2>/dev/null | awk '{print $2}')
  [ -z "$threads" ] && threads="N/A"

  line="$ts | ${cpu}% | ${mem_mb}MB | ${mem_pct}% | $goroutines | $fd_count | $tcp_conns | $threads"
  echo "$line"
  if [ -n "$OUTFILE" ]; then echo "$line" >> "$OUTFILE"; fi

  sleep "$INTERVAL"
done
