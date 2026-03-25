#include "packet_parser.h"
#include <cstring>

static constexpr size_t ETH_HDR   = 14;
static constexpr size_t IP4_MIN   = 20;
static constexpr size_t TCP_MIN   = 20;
static constexpr size_t UDP_HDR   = 8;
static constexpr size_t ICMP_MIN  = 4;

static inline uint16_t u16be(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | p[1];
}

static inline uint32_t u32be(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16)
         | (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}

static size_t eth_decode(const uint8_t* data, size_t len, ParsedPacket& out);
static size_t ip4_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out);
static size_t ip6_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out);
static size_t tcp_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out);
static size_t udp_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out);
static void   icmp_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out);

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& out) {
    out = ParsedPacket{};
    out.valid = false;

    const uint8_t* p   = raw.data;
    const size_t   len = raw.len;

    if (!p || len < ETH_HDR) return false;

    out.raw.ts_sec  = raw.ts_sec;
    out.raw.ts_usec = raw.ts_usec;
    out.raw.seq_num = raw.seq_num;
    out.tuple = {};

    size_t l3_off = eth_decode(p, len, out);
    if (l3_off == 0) return false;

    if (!out.has_ip && !out.is_ipv6) {
        out.valid = true;
        return true;
    }

    size_t l4_off = 0;

    if (out.ip_proto == proto::TCP && !out.is_fragment) {
        l4_off = tcp_decode(p, len, l3_off, out);
    } else if (out.ip_proto == proto::UDP) {
        l4_off = udp_decode(p, len, l3_off, out);
    } else if (out.ip_proto == proto::ICMP) {
        icmp_decode(p, len, l3_off, out);
        out.has_icmp = true;
        out.valid    = true;
        return true;
    }

    if (l4_off > 0 && l4_off <= len) {
        out.payload     = p + l4_off;
        out.payload_len = len - l4_off;
    }

    out.tuple.protocol = out.ip_proto;
    out.tuple.is_ipv6  = out.is_ipv6;

    if (out.is_ipv6) {
        std::memcpy(out.tuple.src_ip, out.src_ip6, 16);
        std::memcpy(out.tuple.dst_ip, out.dst_ip6, 16);
    } else {
        out.tuple.setIPv4(out.src_ip, out.dst_ip);
    }

    out.tuple.src_port = out.src_port;
    out.tuple.dst_port = out.dst_port;
    out.valid = true;
    return true;
}

static size_t eth_decode(const uint8_t* data, size_t len, ParsedPacket& out) {
    if (len < ETH_HDR) return 0;

    std::memcpy(out.dst_mac, data,     6);
    std::memcpy(out.src_mac, data + 6, 6);

    uint16_t et  = u16be(data + 12);
    size_t   off = ETH_HDR;

    if (et == 0x8100) {
        if (len < off + 4) return 0;
        et   = u16be(data + off + 2);
        off += 4;
    }

    out.eth_type = et;

    if (et == proto::ETH_IPV4) {
        if (len < off + IP4_MIN) return 0;
        out.has_ip = true;
        return ip4_decode(data, len, off, out);
    }

    if (et == proto::ETH_IPV6) {
        if (len < off + 40) return 0;
        out.is_ipv6 = true;
        return ip6_decode(data, len, off, out);
    }

    if (et == proto::ETH_ARP) out.app_type = AppType::ARP;
    return off;
}

static size_t ip4_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out) {
    if (off + IP4_MIN > len) return 0;
    const uint8_t* h = data + off;

    uint8_t ihl = (h[0] & 0x0F) * 4;
    if (ihl < 20) return 0;

    out.ip_total_len = u16be(h + 2);
    out.ip_id        = u16be(h + 4);
    out.ttl          = h[8];
    out.ip_proto     = h[9];

    uint16_t frag = u16be(h + 6);
    out.is_fragment  = ((frag & 0x2000) != 0) || ((frag & 0x1FFF) != 0);

    out.src_ip = u32be(h + 12);
    out.dst_ip = u32be(h + 16);
    return off + ihl;
}

static size_t ip6_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out) {
    if (off + 40 > len) return 0;
    const uint8_t* h = data + off;

    out.ip_total_len = u16be(h + 4);
    out.ttl = h[7];

    std::memcpy(out.src_ip6, h + 8,  16);
    std::memcpy(out.dst_ip6, h + 24, 16);

    uint8_t next = h[6];
    off += 40;

    while (off < len) {
        if (next == proto::TCP || next == proto::UDP || next == proto::ICMP) break;
        if (off + 8 > len) break;
        uint8_t ext = (data[off + 1] + 1) * 8;
        next = data[off];
        off += ext;
    }

    out.ip_proto = next;
    return off;
}

static size_t tcp_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out) {
    if (off + TCP_MIN > len) return 0;
    const uint8_t* h = data + off;

    out.has_tcp      = true;
    out.src_port     = u16be(h + 0);
    out.dst_port     = u16be(h + 2);
    out.tcp_seq      = u32be(h + 4);
    out.tcp_ack_num  = u32be(h + 8);
    out.tcp_flags    = h[13];
    out.window_size  = u16be(h + 14);

    uint8_t doff = (h[12] >> 4) * 4;
    if (doff < 20) return 0;
    return off + doff;
}

static size_t udp_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out) {
    if (off + UDP_HDR > len) return 0;
    const uint8_t* h = data + off;
    out.has_udp  = true;
    out.src_port = u16be(h + 0);
    out.dst_port = u16be(h + 2);
    return off + UDP_HDR;
}

static void icmp_decode(const uint8_t* data, size_t len, size_t off, ParsedPacket& out) {
    if (off + ICMP_MIN > len) return;
    (void)data;
    out.app_type = AppType::ICMP;
}

