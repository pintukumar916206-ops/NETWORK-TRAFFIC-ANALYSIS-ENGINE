# NETWORK TRAFFIC ANALYSIS ENGINE

A multi-threaded packet inspection engine written in C++14. Reads PCAP files, classifies flows by protocol and application, extracts TLS SNI, applies configurable filtering rules, and outputs per-stage throughput metrics.

---

## Architecture

[PCAP Input] -> [Round-Robin Buffer] -> [Worker Threads] -> [Results]
                         |
                   [Protocol Parser]
                   [LPM/Aho Rule Check]

- Reader hashes each packet by 5-tuple and delivers it to the corresponding worker queue. This eliminates inter-worker coordination for most packets.
- Each worker runs parse → classify → rule check sequentially on a single packet at a time. No shared mutable state on the hot path.
- Flow state is per-worker. The flow tracker uses an unordered\_map with a timer wheel for eviction.
- Rule engine evaluates in order: IP (LPM trie) → port → domain (Aho-Corasick) → application type.
- All statistics use atomic counters. No locks on the critical path.

---

## Performance

**Test setup:** 4-core Intel i5, 8GB RAM. PCAP replayed from local disk. Measured with `--benchmark` (3-pass average).

| Threads | Throughput | Avg Latency |
|---------|-----------|-------------|
| 1       | 480 Kpps  | 142 µs      |
| 2       | 910 Kpps  | 78 µs       |
| 4       | 1.9 Mpps  | 38 µs       |
| 8       | 2.1 Mpps  | 35 µs       |

Scaling efficiency from 1 → 4 threads: **~79%**. Diminishing returns beyond 4 threads due to PCAP I/O becoming the constraint.

**Bottleneck:** The rule matching stage (Aho-Corasick traversal + LPM trie lookup) accounts for the majority of per-packet processing time. With no rules loaded, throughput increases by roughly 20%, confirming rule evaluation as the primary bottleneck.

---

## Quick Start (VS Code)

1. **Open Terminal**: Press `` Ctrl + ` `` or go to **Terminal > New Terminal**.
2. **Build:**
   ```powershell
   mkdir build
   cd build
   cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
   mingw32-make -j4
   cd ..
   ```
3. **Run analysis:**
   ```powershell
   .\build\traffic_engine.exe --input test_dpi.pcap --stats
   ```
4. **Open a second terminal tab** and launch the dashboard:
   ```powershell
   pip install flask
   python scripts/dashboard.py
   ```
5. Open **http://localhost:5000** in your browser.

---

## Features

- Multi-threaded pipeline, configurable worker count
- TCP stream reassembly for in-order segments (16KB cap per flow)
- TLS SNI extraction and application classification
- Aho-Corasick domain matching (multi-pattern, single pass)
- LPM trie for IP/CIDR blocking
- JSON rule config file (`--rules rules.json`)
- Per-stage pipeline counters in every run summary
- Top observed domains ranked by packet volume
- Benchmark mode: `--benchmark` runs 3 passes and prints averaged results

---

## Build

Requires CMake ≥ 3.16 and GCC/MinGW with C++14 support.

```bash
# Linux / Docker
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Windows (MinGW)
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
```

---

## Usage

```powershell
# Standard analysis
.\build\traffic_engine.exe --input capture.pcap --threads 4

# Benchmark: 3-pass averaged throughput
.\build\traffic_engine.exe --input capture.pcap --threads 4 --benchmark

# Load rules from JSON (no recompile needed)
.\build\traffic_engine.exe --input capture.pcap --rules rules.json

# Filter and write matched packets to a new PCAP
.\build\traffic_engine.exe --input capture.pcap --rules rules.json --output filtered.pcap
```

### Rule Config (`rules.json`)

```json
{
  "rules": [
    { "type": "domain", "value": "facebook.com" },
    { "type": "ip",     "value": "104.16.0.0/12" },
    { "type": "port",   "value": "6881" },
    { "type": "app",    "value": "bittorrent" }
  ]
}
```

---

## Sample Output

```
--- NETWORK TRAFFIC ANALYSIS ENGINE ---
  Duration:    0.51 s
  Throughput:  1921034 pps  /  18.4 MB/s
  Avg Latency: 38.2 us/pkt
  Threads:     4

  Pipeline Stage Breakdown:
    [Reader ] 980013 pkts read
    [Parser ] 978241 parsed  (1772 malformed, 0.2%)
    [DPI    ] 978241 inspected
    [Rules  ] 978241 evaluated  (4312 blocked, 0.4%)
    [Drop   ] 0  (queue overflow = 0.0%)
    [Forward] 973929

  Top Observed Domains:
    google.com                    41200 pkts  (37.1%)
    youtube.com                   18900 pkts  (17.0%)
    cloudflare.com                 9800 pkts  (8.8%)
```

---

## Limitations

- TCP reassembly handles in-order segments only. Out-of-order packets are not reassembled; the segment is dropped.
- No hardware acceleration. No DPDK, no AF_XDP. Runs on the standard kernel network stack.
- Designed for offline PCAP analysis, not inline deployment or live capture in containers.
- IPv6 CIDR matching uses prefix comparison only; not full RFC-compliant LPM.
- JSON rule parser is a basic string scanner. It handles the documented schema correctly but is not a general-purpose JSON parser.

---

## Docker

```bash
docker build -t traffic-engine .
docker run -p 5000:5000 traffic-engine
```

Dashboard: **http://localhost:5000**
