# High-Performance DPI Engine 

A multi-threaded Deep Packet Inspection (DPI) engine implemented in C++. It handles flow classification (TLS SNI, HTTP Host) at high speeds using a pipelined architecture.

This project was built to explore low-level networking, lock-free concurrency, and efficient pattern matching. It's an engineering exercise, not a commercial product.

---

**Architecture Overview:**
Built using a sharded-worker pipeline to minimize context switching and lock-contention. It uses a custom memory slab for buffer management and an Aho-Corasick automaton for multi-pattern domain matching.

---

## Challenges & Known Limitations

- **Memory Slab Migration:** Built a custom buffer reservoir to minimize allocation overhead. On Linux, this is designed to be backed by **AF_XDP/DPDK** for 100G wire rates.
- **Aho-Corasick Memory:** The pattern matcher uses a flat transition table (256 pointers per node). It's fast ($O(1)$ lookup) but memory-intensive.
- **IPv6:** Basic parsing is supported, but the Rules Engine currently has limited support for complex IPv6 CIDR ranges.
- **Security:** It's a DPI engine, but it's not "hardened." It hasn't been tested against TCP evasion techniques like overlapping segments.

---

## Deployment

### Using Docker

```bash
docker compose up --build -d
```

The dashboard will be available at: **http://localhost:5000**

### Local Build

Requires CMake (minimum 3.16) and a C++14 compiler (GCC/MinGW recommended).

**Using MinGW (Required if you don't have Visual Studio installed):**
On Windows, you must explicitly specify the MinGW generator to avoid the default Visual Studio failure:

```bash
mkdir build && cd build
cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
mingw32-make -j4
```

**Using Visual Studio:**

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

---

## Running the Engine (Terminal Only)

Once built, run the engine directly from your terminal:

```powershell
# For MinGW builds:
.\build\high_performance_engine.exe --input test_dpi.pcap --stats --loop --delay 2000

# For Visual Studio builds:
.\build\Release\high_performance_engine.exe --input test_dpi.pcap --stats --loop --delay 2000
```

### 2. Start the Web Dashboard (Optional)

In a **new terminal**, run the Python side to see the UI:

```powershell
pip install -r requirements.txt
python scripts/dashboard.py
```

Dashboard available at: **[http://localhost:5000](http://localhost:5000)**

---

## Core Engineering Architecture

The design borrows heavily from industry standard engines like Snort 3 and Suricata. The goal was to prove that you can achieve high throughput on standard hardware if you respect the CPU cache and avoid unnecessary locking.

