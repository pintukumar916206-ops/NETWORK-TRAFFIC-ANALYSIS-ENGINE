#pragma once
 
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>
 
// Protocol Constants
namespace proto {
    constexpr uint8_t  ICMP       =   1;
    constexpr uint8_t  TCP        =   6;
    constexpr uint8_t  UDP        =  17;
    constexpr uint16_t ETH_IPV4   = 0x0800;
    constexpr uint16_t ETH_ARP    = 0x0806;
    constexpr uint16_t ETH_IPV6   = 0x86DD;
    constexpr uint16_t PORT_FTP   =    21;
    constexpr uint16_t PORT_SSH   =    22;
    constexpr uint16_t PORT_SMTP  =    25;
    constexpr uint16_t PORT_DNS   =    53;
    constexpr uint16_t PORT_HTTP  =    80;
    constexpr uint16_t PORT_NTP   =   123;
    constexpr uint16_t PORT_HTTPS =   443;
    constexpr uint16_t PORT_SMTPS =   587;
}
// Core data structures for the NETWORK TRAFFIC ANALYSIS ENGINE.
namespace tcp_flags {
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
}
 
// L7 Application Types
enum class AppType : uint8_t {
    UNKNOWN    =  0,
    HTTP       =  1,
    HTTPS      =  2,
    DNS        =  3,
    FTP        =  4,
    SSH        =  5,
    SMTP       =  6,
    NTP        =  7,
    TLS_OTHER  =  8,
    GOOGLE     =  9,
    YOUTUBE    = 10,
    FACEBOOK   = 11,
    TWITTER    = 12,
    INSTAGRAM  = 13,
    NETFLIX    = 14,
    AMAZON     = 15,
    MICROSOFT  = 16,
    CLOUDFLARE = 17,
    GITHUB     = 18,
    BITTORRENT = 19,
    QUIC       = 20,
    ICMP       = 21,
    ARP        = 22,
};
 
// Forward-declared helpers; defined in types.cpp
std::string appTypeToString(AppType t);
AppType     sniToAppType(const std::string& sni);
std::string ipToString(const uint8_t* ip, bool is_ipv6);
 
// Raw Packet Data - Cache-aligned (64 bytes) to prevent false sharing and optimize SIMD
struct alignas(64) RawPacket {
    uint8_t* data     = nullptr; // Pointer into pre-allocated pool (avoids data copies)
    uint32_t len      = 0;       // Captured length
    uint32_t ts_sec   = 0;
    uint32_t ts_usec  = 0;
    uint32_t orig_len = 0;       // Wire length before snap truncation
    uint64_t seq_num  = 0;       // Monotonic arrival sequence number
    
    // Internal pool management
    void*    _pool_ref = nullptr; 

    // Helper for easier transition
    bool empty() const noexcept { return data == nullptr || len == 0; }
    size_t size() const noexcept { return static_cast<size_t>(len); }
};
 
// Five-Tuple (Flow Key)
struct FiveTuple {
    uint8_t  src_ip[16] = {0};
    uint8_t  dst_ip[16] = {0};
    uint16_t src_port   = 0;
    uint16_t dst_port   = 0;
    uint8_t  protocol   = 0;
    bool     is_ipv6    = false;

    bool operator==(const FiveTuple& o) const noexcept {
        return is_ipv6 == o.is_ipv6 &&
               protocol == o.protocol &&
               src_port == o.src_port &&
               dst_port == o.dst_port &&
               std::memcmp(src_ip, o.src_ip, 16) == 0 &&
               std::memcmp(dst_ip, o.dst_ip, 16) == 0;
    }

    FiveTuple canonical() const noexcept {
        bool swap = false;
        int cmp = std::memcmp(src_ip, dst_ip, 16);
        if (cmp < 0) swap = false;
        else if (cmp > 0) swap = true;
        else swap = (src_port > dst_port);

        if (!swap) return *this;
        FiveTuple out = *this;
        std::memcpy(out.src_ip, dst_ip, 16);
        std::memcpy(out.dst_ip, src_ip, 16);
        out.src_port = dst_port;
        out.dst_port = src_port;
        return out;
    }

    void setIPv4(uint32_t src, uint32_t dst) {
        is_ipv6 = false;
        std::memset(src_ip, 0, 16);
        std::memset(dst_ip, 0, 16);
        // Store in first 4 bytes for simplicity (host order here usually)
        std::memcpy(src_ip, &src, 4);
        std::memcpy(dst_ip, &dst, 4);
    }
};
 
// FNV-1a based hasher — fast and well-distributed for IP tuples
struct FiveTupleHash {
    std::size_t operator()(const FiveTuple& t) const noexcept {
        constexpr uint64_t BASIS = 14695981039346656037ULL;
        constexpr uint64_t PRIME = 1099511628211ULL;
        uint64_t h = BASIS;
        auto eat_bytes = [&](const uint8_t* p, size_t len) {
            for (size_t i = 0; i < len; ++i) h = (h ^ p[i]) * PRIME;
        };
        eat_bytes(t.src_ip, 16);
        eat_bytes(t.dst_ip, 16);
        uint16_t ports[2] = { t.src_port, t.dst_port };
        eat_bytes(reinterpret_cast<const uint8_t*>(ports), 4);
        h = (h ^ t.protocol) * PRIME;
        h = (h ^ (t.is_ipv6 ? 1 : 0)) * PRIME;
        return static_cast<std::size_t>(h);
    }
};
 
// Parsed Packet View
struct ParsedPacket {
    // ── Layer 2 ──────────────────────────────────────
    uint8_t  src_mac[6]   = {};
    uint8_t  dst_mac[6]   = {};
    uint16_t eth_type     = 0;
 
    // ── Layer 3 ──────────────────────────────────────
    bool     has_ip       = false;
    bool     is_ipv6      = false;
    uint8_t  src_ip6[16]  = {0};
    uint8_t  dst_ip6[16]  = {0};
    uint32_t src_ip       = 0;   // host order (v4 only)
    uint32_t dst_ip       = 0;
    uint8_t  ip_proto     = 0;
    uint8_t  ttl          = 0;
    uint16_t ip_id        = 0;
    uint16_t ip_total_len = 0;
    bool     is_fragment  = false;
 
    // ── Layer 4 ──────────────────────────────────────
    bool     has_tcp      = false;
    bool     has_udp      = false;
    bool     has_icmp     = false;
    uint16_t src_port     = 0;
    uint16_t dst_port     = 0;
    uint32_t tcp_seq      = 0;
    uint32_t tcp_ack_num  = 0;
    uint8_t  tcp_flags    = 0;
    uint16_t window_size  = 0;
 
    // ── Layer 7 ──────────────────────────────────────
    const uint8_t* payload     = nullptr;  // pointer into raw data vector
    size_t         payload_len = 0;
    AppType        app_type    = AppType::UNKNOWN;
    std::string    sni;                    // TLS SNI or HTTP Host header
 
    // ── Meta ─────────────────────────────────────────
    FiveTuple tuple;
    bool      valid       = false;
    bool      sni_seen    = false;   // set once TLS SNI is extracted
 
    // Lightweight copy of the raw packet metadata so the flow tracker
    // can record per-flow timestamps without holding a full RawPacket.
    struct RawMeta {
        uint32_t ts_sec   = 0;
        uint32_t ts_usec  = 0;
        uint64_t seq_num  = 0;
    } raw;
 
    std::string srcIPStr() const { return ipToString(src_ip6, is_ipv6 ? true : false); }
    std::string dstIPStr() const { return ipToString(dst_ip6, is_ipv6 ? true : false); }
};
 
// Flow Record
struct Flow {
    FiveTuple   key;
    AppType     app_type      = AppType::UNKNOWN;
    std::string sni;
 
    uint64_t    pkt_count     = 0;
    uint64_t    byte_count    = 0;
    uint32_t    first_ts_sec  = 0;
    uint32_t    first_ts_usec = 0;
    uint32_t    last_ts_sec   = 0;
    uint32_t    last_ts_usec  = 0;
 
    bool        blocked       = false;  // latched once; all later pkts drop
    bool        sni_seen      = false;  // avoid re-parsing TLS on every pkt

    // TCP Reassembly State
    std::vector<uint8_t> reassembly_buffer;
    uint32_t             expected_seq = 0;
    bool                 dpi_complete = false;

    // Returns true if segment was appended successfully
    bool appendSegment(uint32_t seq, const uint8_t* data, uint64_t len) {
        if (dpi_complete) return false;
        if (expected_seq == 0) expected_seq = seq;
        if (seq != expected_seq) return false;
        
        reassembly_buffer.insert(reassembly_buffer.end(), data, data + static_cast<size_t>(len));
        expected_seq += static_cast<uint32_t>(len);
        
        // Cap at 16KB for DPI
        if (reassembly_buffer.size() > 16384) dpi_complete = true;
        return true;
    }
 
    double durationSec()   const noexcept;
    double throughputBps() const noexcept;
    std::string srcIPStr() const { return ipToString(key.src_ip, key.is_ipv6); }
    std::string dstIPStr() const { return ipToString(key.dst_ip, key.is_ipv6); }

    std::string toJSON() const {
        return "{\"src\":\"" + srcIPStr() + "\",\"dst\":\"" + dstIPStr() + "\"," +
               "\"sp\":" + std::to_string(key.src_port) + ",\"dp\":" + std::to_string(key.dst_port) + "," +
               "\"app\":\"" + appTypeToString(app_type) + "\",\"bytes\":" + std::to_string(byte_count) + "," +
               "\"pkts\":" + std::to_string(pkt_count) + ",\"sni\":\"" + sni + "\"," +
               "\"blocked\":" + (blocked ? "true" : "false") + "}";
    }
};
 
// Global Statistics
struct Stats {
    std::atomic<uint64_t> total_packets     { 0 };
    std::atomic<uint64_t> total_bytes       { 0 };
    std::atomic<uint64_t> tcp_packets       { 0 };
    std::atomic<uint64_t> udp_packets       { 0 };
    std::atomic<uint64_t> icmp_packets      { 0 };
    std::atomic<uint64_t> arp_packets       { 0 };
    std::atomic<uint64_t> dropped_packets   { 0 };   // queue overflow drops
    std::atomic<uint64_t> blocked_packets   { 0 };   // rule-based blocks
    std::atomic<uint64_t> forwarded_packets { 0 };
    std::atomic<uint64_t> malformed_packets { 0 };
    std::atomic<uint64_t> total_latency_ns  { 0 };   // cumulative processing ns
 
    std::chrono::steady_clock::time_point start_time{
        std::chrono::steady_clock::now() };
 
    double elapsedSec() const noexcept {
        using namespace std::chrono;
        return duration<double>(steady_clock::now() - start_time).count();
    }
    double throughputPps() const noexcept {
        double t = elapsedSec();
        return t > 0 ? double(total_packets.load()) / t : 0.0;
    }
    double avgLatencyMs() const noexcept {
        uint64_t p = total_packets.load();
        return p > 0 ? double(total_latency_ns.load()) / double(p) / 1e6 : 0.0;
    }
    double avgLatencyUs() const noexcept {
        uint64_t p = total_packets.load();
        return p > 0 ? double(total_latency_ns.load()) / double(p) / 1e3 : 0.0;
    }
    double throughputMBps() const noexcept {
        double t = elapsedSec();
        return t > 0 ? double(total_bytes.load()) / t / (1024.0 * 1024.0) : 0.0;
    }
    double dropRatePct() const noexcept {
        uint64_t t = total_packets.load();
        return t > 0 ? 100.0 * double(dropped_packets.load()) / double(t) : 0.0;
    }
    double blockRatePct() const noexcept {
        uint64_t t = total_packets.load();
        return t > 0 ? 100.0 * double(blocked_packets.load()) / double(t) : 0.0;
    }

    std::string toJSON() const {
        return "{\"total_packets\":" + std::to_string(total_packets.load()) + "," +
               "\"total_bytes\":" + std::to_string(total_bytes.load()) + "," +
               "\"tcp\":" + std::to_string(tcp_packets.load()) + "," +
               "\"udp\":" + std::to_string(udp_packets.load()) + "," +
               "\"icmp\":" + std::to_string(icmp_packets.load()) + "," +
               "\"blocked\":" + std::to_string(blocked_packets.load()) + "," +
               "\"dropped\":" + std::to_string(dropped_packets.load()) + "," +
               "\"pps\":" + std::to_string(throughputPps()) + "," +
               "\"latency_ms\":" + std::to_string(avgLatencyMs()) + "}";
    }
 
    // Reset all counters and restart the clock
    void reset() noexcept {
        total_packets.store(0);
        total_bytes.store(0);
        tcp_packets.store(0);
        udp_packets.store(0);
        icmp_packets.store(0);
        arp_packets.store(0);
        dropped_packets.store(0);
        blocked_packets.store(0);
        forwarded_packets.store(0);
        malformed_packets.store(0);
        total_latency_ns.store(0);
        start_time = std::chrono::steady_clock::now();
    }
 
    // Atomics are not copyable
    Stats(const Stats&)            = delete;
    Stats& operator=(const Stats&) = delete;
    Stats()                        = default;
};
