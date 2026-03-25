#include "dpi_pipeline.h"
#include "packet_pool.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <unordered_map>

DpiPipeline::DpiPipeline(Config cfg)
    : cfg_(cfg), output_queue_(cfg.queue_capacity)
{
    worker_queues_.reserve(cfg_.num_workers);
    flow_trackers_.reserve(cfg_.num_workers);
    for (int i = 0; i < cfg_.num_workers; ++i) {
        worker_queues_.push_back(std::make_unique<LockFreeQueue<RawPacket>>(cfg_.queue_capacity));
        flow_trackers_.push_back(std::make_unique<FlowTracker>(i));
    }
}

void DpiPipeline::addBlockIP(const std::string& ip)          { rules_.addBlockIP(ip); }
void DpiPipeline::addBlockDomain(const std::string& domain)  { rules_.addBlockDomain(domain); }
void DpiPipeline::addBlockPort(uint16_t port)                { rules_.addBlockPort(port); }
void DpiPipeline::loadRules(const std::string& path)         { rules_.loadFromFile(path); }

void DpiPipeline::addBlockApp(const std::string& name) {
    static const struct { const char* key; AppType val; } table[] = {
        { "youtube",    AppType::YOUTUBE    },
        { "facebook",   AppType::FACEBOOK   },
        { "netflix",    AppType::NETFLIX    },
        { "bittorrent", AppType::BITTORRENT },
    };
    for (auto& e : table) {
        if (name == e.key) { rules_.addBlockApp(e.val); return; }
    }
}

void DpiPipeline::run() {
    rules_.buildAutomata();

    std::cout << "Starting NETWORK TRAFFIC ANALYSIS ENGINE (" << cfg_.num_workers << " workers)...\n";
    if (rules_.hasRules()) {
        std::cout << "Active Rules:\n";
        rules_.printRules();
    }

    compat::thread reader([this] { readerThread(); });

    std::vector<std::unique_ptr<compat::thread>> workers;
    workers.reserve(cfg_.num_workers);
    for (int i = 0; i < cfg_.num_workers; ++i)
        workers.push_back(std::make_unique<compat::thread>([this, i] { workerThread(i); }));

    compat::thread writer([this] { writerThread(); });

    std::unique_ptr<compat::thread> stats;
    if (cfg_.live_stats)
        stats = std::make_unique<compat::thread>([this] { statsThread(); });

    reader.join();

    for (auto& q : worker_queues_)
        q->shutdown();
    output_queue_.shutdown();

    for (auto& w : workers) w->join();
    writer.join();
    if (stats) stats->join();

    for (const auto& ft : flow_trackers_) {
        auto snap = ft->snapshot();
        all_flows_.insert(all_flows_.end(), snap.begin(), snap.end());
    }
}

void DpiPipeline::readerThread() {
    PcapReader reader;
    if (!reader.open(cfg_.input_file)) {
        std::cerr << "[ERROR] Could not open input file: " << cfg_.input_file << "\n";
        for (auto& q : worker_queues_) q->shutdown();
        return;
    }

    FiveTupleHash hasher;
    RawPacket raw;

    while (reader.nextPacket(raw)) {
        FiveTuple tup;
        if (!quickTuple(raw, tup)) {
            stats_.malformed_packets.fetch_add(1);
            PacketPool::instance().release(raw);
            continue;
        }
        size_t idx = hasher(tup.canonical()) % static_cast<size_t>(cfg_.num_workers);
        if (!worker_queues_[idx]->push(std::move(raw))) {
            PacketPool::instance().release(raw);
            break;
        }
    }

    for (auto& q : worker_queues_) q->shutdown();
}

void DpiPipeline::workerThread(int id) {
    auto& queue   = *worker_queues_[id];
    auto& tracker = *flow_trackers_[id];

    while (true) {
        auto item = queue.pop();
        if (!item) break;

        RawPacket& raw = *item;
        auto t0 = std::chrono::steady_clock::now();

        stats_.total_packets.fetch_add(1);
        stats_.total_bytes.fetch_add(raw.len);

        ParsedPacket pkt;
        if (!PacketParser::parse(raw, pkt)) {
            stats_.malformed_packets.fetch_add(1);
            PacketPool::instance().release(raw);
            continue;
        }

        if      (pkt.ip_proto == proto::TCP)  stats_.tcp_packets.fetch_add(1);
        else if (pkt.ip_proto == proto::UDP)  stats_.udp_packets.fetch_add(1);
        else if (pkt.ip_proto == proto::ICMP) stats_.icmp_packets.fetch_add(1);

        Flow* flow = tracker.update(pkt);

        if (!flow->sni_seen && pkt.payload && pkt.payload_len > 0) {
            const uint8_t* buf = pkt.payload;
            size_t         blen = pkt.payload_len;
            bool try_dpi = false;

            if (pkt.has_tcp) {
                if (flow->appendSegment(pkt.tcp_seq, pkt.payload, pkt.payload_len)) {
                    buf  = flow->reassembly_buffer.data();
                    blen = flow->reassembly_buffer.size();
                    try_dpi = true;
                }
            } else if (pkt.has_udp) {
                try_dpi = true;
            }

            if (try_dpi) {
                auto sni = SNIExtractor::extract(buf, blen);
                if (sni) {
                    flow->sni      = *sni;
                    flow->app_type = sniToAppType(*sni);
                    flow->sni_seen = true;
                } else if (BitTorrentDetector::detect(buf, blen)) {
                    flow->app_type = AppType::BITTORRENT;
                    flow->sni_seen = true;
                } else if (flow->dpi_complete) {
                    flow->sni_seen = true;
                }
            }
        }

        bool blocked = flow->blocked || rules_.shouldBlock(pkt, *flow);
        if (blocked) {
            flow->blocked = true;
            stats_.blocked_packets.fetch_add(1);
            PacketPool::instance().release(raw);
        } else {
            stats_.forwarded_packets.fetch_add(1);
            if (!cfg_.output_file.empty())
                output_queue_.push(std::move(raw));
            else
                PacketPool::instance().release(raw);
        }

        auto t1 = std::chrono::steady_clock::now();
        stats_.total_latency_ns.fetch_add(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count());

        if (stats_.total_packets.load() % 10000 == 0)
            tracker.evictStale(raw.ts_sec);
    }
    workers_done_.fetch_add(1);
}

void DpiPipeline::writerThread() {
    if (cfg_.output_file.empty()) return;

    PcapWriter writer;
    if (!writer.open(cfg_.output_file)) {
        std::cerr << "[ERROR] Could not open output file: " << cfg_.output_file << "\n";
        return;
    }

    while (true) {
        auto item = output_queue_.pop();
        if (!item) break;
        writer.writePacket(*item);
        PacketPool::instance().release(*item);
    }
}

void DpiPipeline::statsThread() {
    while (workers_done_.load() < cfg_.num_workers) {
        compat::sleep_ms(1000);
        std::cout << "[STATS] "
                  << std::fixed << std::setprecision(0) << stats_.throughputPps() << " pps | "
                  << "Latency: " << std::setprecision(2) << stats_.avgLatencyMs() << " ms | "
                  << "Blocks: " << stats_.blocked_packets.load() << "\n";
    }
}

bool DpiPipeline::quickTuple(const RawPacket& raw, FiveTuple& out) {
    if (raw.len < 14) return false;

    const uint8_t* d = raw.data;
    uint16_t etype = (uint16_t(d[12]) << 8) | d[13];

    if (etype == proto::ETH_IPV4) {
        if (raw.len < 34) return false;

        uint32_t sip = (uint32_t(d[26]) << 24) | (uint32_t(d[27]) << 16)
                     | (uint32_t(d[28]) << 8)  |  uint32_t(d[29]);
        uint32_t dip = (uint32_t(d[30]) << 24) | (uint32_t(d[31]) << 16)
                     | (uint32_t(d[32]) << 8)  |  uint32_t(d[33]);
        out.setIPv4(sip, dip);
        out.protocol = d[23];

        size_t l4 = 14 + (d[14] & 0x0F) * 4;
        if (raw.len < l4 + 4) return false;

        out.src_port = (uint16_t(d[l4])   << 8) | d[l4 + 1];
        out.dst_port = (uint16_t(d[l4+2]) << 8) | d[l4 + 3];
        return true;
    }

    if (etype == proto::ETH_IPV6) {
        if (raw.len < 54) return false;
        out.is_ipv6 = true;
        std::memcpy(out.src_ip, d + 22, 16);
        std::memcpy(out.dst_ip, d + 38, 16);
        out.protocol = d[20];
        out.src_port = (uint16_t(d[54]) << 8) | d[55];
        out.dst_port = (uint16_t(d[56]) << 8) | d[57];
        return true;
    }

    return false;
}

void DpiPipeline::printSummary() const {
    uint64_t total     = stats_.total_packets.load();
    uint64_t bad       = stats_.malformed_packets.load();
    uint64_t parsed    = total - bad;
    uint64_t blocked   = stats_.blocked_packets.load();
    uint64_t dropped   = stats_.dropped_packets.load();
    uint64_t forwarded = stats_.forwarded_packets.load();

    auto pct = [](uint64_t n, uint64_t d) -> double {
        return d > 0 ? 100.0 * double(n) / double(d) : 0.0;
    };

    std::cout << "\n--- NETWORK TRAFFIC ANALYSIS ENGINE ---\n"
              << "  Duration:    " << std::fixed << std::setprecision(2)
                                   << stats_.elapsedSec() << " s\n"
              << "  Throughput:  " << std::setprecision(0) << stats_.throughputPps()
                                   << " pps  /  " << std::setprecision(1)
                                   << stats_.throughputMBps() << " MB/s\n"
              << "  Avg Latency: " << stats_.avgLatencyUs() << " us/pkt\n"
              << "  Threads:     " << cfg_.num_workers << "\n\n";

    std::cout << "  Pipeline Stage Breakdown:\n"
              << "    [Reader ] " << total << " pkts read\n"
              << "    [Parser ] " << parsed << " parsed"
              << "  (" << bad << " malformed, "
              << std::setprecision(1) << pct(bad, total) << "%)\n"
              << "    [DPI    ] " << parsed << " inspected\n"
              << "    [Rules  ] " << parsed << " evaluated"
              << "  (" << blocked << " blocked, " << pct(blocked, parsed) << "%)\n"
              << "    [Drop   ] " << dropped
              << "  (queue overflow = " << pct(dropped, total) << "%)\n"
              << "    [Forward] " << forwarded << "\n"
              << "\n  Protocol Mix:  TCP " << stats_.tcp_packets.load()
              << " / UDP " << stats_.udp_packets.load()
              << " / ICMP " << stats_.icmp_packets.load() << "\n";

    std::unordered_map<std::string, uint64_t> by_domain;
    for (const auto& f : all_flows_) {
        if (!f.sni.empty())
            by_domain[f.sni] += f.pkt_count;
    }

    if (!by_domain.empty()) {
        std::vector<std::pair<std::string, uint64_t>> ranked(by_domain.begin(), by_domain.end());
        std::sort(ranked.begin(), ranked.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        uint64_t total_dpkts = 0;
        for (auto& kv : ranked) total_dpkts += kv.second;

        std::cout << "\n  Top Observed Domains:\n";
        size_t show = std::min(ranked.size(), size_t(8));
        for (size_t i = 0; i < show; ++i) {
            double share = total_dpkts > 0
                ? 100.0 * double(ranked[i].second) / double(total_dpkts) : 0.0;
            std::cout << "    " << std::left << std::setw(30) << ranked[i].first
                      << std::right << std::setw(8) << ranked[i].second << " pkts"
                      << "  (" << std::fixed << std::setprecision(1) << share << "%)\n";
        }
    }

    std::vector<Flow> top = all_flows_;
    std::sort(top.begin(), top.end(), [](const Flow& a, const Flow& b) {
        return a.byte_count > b.byte_count;
    });

    if (!top.empty()) {
        std::cout << "\n  Top Flows by Volume:\n";
        for (size_t i = 0; i < std::min(top.size(), size_t(5)); ++i) {
            const auto& f = top[i];
            std::cout << "    " << std::setw(15) << f.srcIPStr() << ":" << std::setw(5) << f.key.src_port
                      << " -> " << std::setw(15) << f.dstIPStr() << ":" << std::setw(5) << f.key.dst_port
                      << "  [" << std::setw(10) << appTypeToString(f.app_type) << "] "
                      << f.byte_count / 1024 << " KB";
            if (!f.sni.empty()) std::cout << "  (" << f.sni << ")";
            std::cout << "\n";
        }
    }
    std::cout << "----------------------------\n\n";
}

void DpiPipeline::printSummaryJson() const {
    std::vector<Flow> top = all_flows_;
    std::sort(top.begin(), top.end(), [](const Flow& a, const Flow& b) {
        return a.byte_count > b.byte_count;
    });

    std::cout << "{\"stats\":" << stats_.toJSON() << ",\"flows\":[";
    size_t limit = std::min(top.size(), size_t(50));
    for (size_t i = 0; i < limit; ++i) {
        std::cout << top[i].toJSON();
        if (i + 1 < limit) std::cout << ",";
    }
    std::cout << "]}\n";
}
