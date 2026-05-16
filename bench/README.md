# GoWAF 压测套件

针对 1核1G Linux 环境下 GoWAF 的完整压测方案。

## 目录结构

```
bench/
├── README.md                    # 本文件
├── scripts/
│   ├── run_all.sh               # 一键运行所有场景
│   ├── run_scenario.sh          # 运行单个场景
│   ├── s1_clean_traffic.sh      # 场景1: 干净流量吞吐量
│   ├── s2_malicious_traffic.sh  # 场景2: 恶意流量检测
│   ├── s3_high_concurrency.sh   # 场景3: 高并发连接
│   ├── s4_multi_ip.sh           # 场景4: 大量唯一IP
│   ├── s5_large_payload.sh      # 场景5: 大请求体
│   ├── s6_realistic_mix.sh      # 场景6: 混合流量模拟
│   ├── s7_endurance.sh          # 场景7: 长时间稳定性
│   ├── s8_special_attacks.sh    # 场景8: 特殊攻击模式
│   └── monitor.sh               # WAF服务端监控脚本
├── lua/
│   ├── clean_traffic.lua        # 干净流量多路径
│   ├── sqli_attack.lua          # SQL注入载荷
│   ├── xss_attack.lua           # XSS载荷
│   ├── cmdi_attack.lua          # 命令注入载荷
│   ├── path_traversal_attack.lua# 路径遍历载荷
│   ├── mixed_attack.lua         # 混合攻击载荷
│   ├── post_attack.lua          # POST恶意请求体
│   ├── short_conn.lua           # 短连接模式
│   ├── multi_ip.lua             # 多IP模拟(正常)
│   ├── multi_ip_attack.lua      # 多IP模拟(攻击)
│   ├── large_body.lua           # 大请求体
│   ├── mixed_methods.lua        # 混合HTTP方法
│   └── scanner_sim.lua          # 扫描器模拟
└── results/                     # 测试结果输出目录
```

## 环境准备

### 1. 安装 wrk（在压测机上）

```bash
git clone https://github.com/wg/wrk.git && cd wrk && make -j$(nproc) && sudo cp wrk /usr/local/bin/
```

### 2. WAF 服务端准备

```bash
# 提升文件描述符限制
ulimit -n 65535

# 启动 WAF 服务
./waf

# 另开终端运行监控
bash bench/scripts/monitor.sh 2 /tmp/waf_monitor.log
```

## 运行方式

### 一键运行所有场景

```bash
bash bench/scripts/run_all.sh http://WAF地址:端口
```

### 运行单个场景

```bash
# 场景1: 干净流量基准
bash bench/scripts/run_scenario.sh 1 http://WAF地址:端口

# 场景2: 恶意流量检测
bash bench/scripts/run_scenario.sh 2 http://WAF地址:端口

# 场景3: 高并发连接
bash bench/scripts/run_scenario.sh 3 http://WAF地址:端口
```

### 直接执行某个脚本

```bash
bash bench/scripts/s1_clean_traffic.sh
bash bench/scripts/s2_malicious_traffic.sh
```

## 场景说明

| 场景 | 名称 | 关注指标 | 1核1G 预估 |
|------|------|----------|-----------|
| 1 | 干净流量吞吐量 | QPS拐点、P99延迟 | 2000-5000 QPS |
| 2 | 恶意流量检测 | CPU满载点、检测延迟 | 500-1500 QPS |
| 3 | 高并发连接 | 内存增长、Goroutine数 | ~2000并发连接 |
| 4 | 大量唯一IP | 限流器内存、锁竞争 | ~2万唯一IP |
| 5 | 大请求体 | 内存翻倍、I/O延迟 | ~200并发(1MB) |
| 6 | 混合流量(80/15/5) | 综合QPS、错误率 | 取决于规则配置 |
| 7 | 长时间稳定性 | 内存趋势、Goroutine泄漏 | 持续1-4小时 |
| 8 | 特殊攻击模式 | 限流触发率、方法拦截 | — |

## 关键指标说明

- **QPS**: 每秒请求数，关注 wrk 输出的 `Requests/sec`
- **P50/P90/P99 延迟**: wrk `--latency` 输出的延迟分布
- **CPU**: 监控脚本输出的 CPU 占比，100% 为单核满载
- **内存RSS**: 实际物理内存占用，1G 环境下 >800MB 有 OOM 风险
- **Goroutine**: Go 协程数，持续增长说明有泄漏
- **FD数**: 文件描述符数，接近 ulimit 上限会导致新连接失败
- **日志丢失率**: 通过 WAF 管理 API 查询 `logger.GetDropCount()`

## 注意事项

1. **压测机应独立于 WAF 服务器**，避免互相争抢资源
2. 场景3/4 之间留 10s 间隔，让 WAF 释放资源
3. 场景7 耗时最长(1小时+)，建议最后运行
4. 所有结果保存在 `bench/results/` 目录
5. 如需修改目标地址，编辑脚本顶部 `TARGET` 变量
