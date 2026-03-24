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
    : cfg_(cfg), output_queue_(cfg.queue_capacity) {
    
    // Initialize per-worker components
    for (int i = 0; i < cfg_.num_workers; ++i) {
        worker_queues_.push_back(std::make_unique<LockFreeQueue<RawPacket>>(cfg_.queue_capacity));
        flow_trackers_.push_back(std::make_unique<FlowTracker>(i));
    }
}

void DpiPipeline::addBlockIP(const std::string& ip) { rules_.addBlockIP(ip); }
void DpiPipeline::addBlockDomain(const std::string& d) { rules_.addBlockDomain(d); }
void DpiPipeline::addBlockPort(uint16_t p) { rules_.addBlockPort(p); }
void DpiPipeline::loadRules(const std::string& path) { rules_.loadFromFile(path); }
void DpiPipeline::addBlockApp(const std::string& a) {
    if (a == "youtube") rules_.addBlockApp(AppType::YOUTUBE);
    else if (a == "facebook") rules_.addBlockApp(AppType::FACEBOOK);
    else if (a == "netflix") rules_.addBlockApp(AppType::NETFLIX);
    else if (a == "bittorrent") rules_.addBlockApp(AppType::BITTORRENT);
}

void DpiPipeline::run() {
    // Finalize rules
    rules_.buildAutomata();

    std::cout << "Starting NETWORK TRAFFIC ANALYSIS ENGINE (" << cfg_.num_workers << " workers)...\n";
    if (rules_.hasRules()) {
        std::cout << "Active Rules:\n";
        rules_.printRules();
    }

    // Start the pipeline threads
    compat::thread reader_t([this]{ this->readerThread(); });
    
    std::vector<std::unique_ptr<compat::thread>> workers;
    for (int i = 0; i < cfg_.num_workers; ++i) {
        workers.push_back(std::make_unique<compat::thread>([this, i]{ this->workerThread(i); }));
    }

    compat::thread writer_t([this]{ this->writerThread(); });
    
    std::unique_ptr<compat::thread> stats_t;
    if (cfg_.live_stats) {
        stats_t = std::make_unique<compat::thread>([this]{ this->statsThread(); });
    }

    // 2. Wait for reader to finish
    reader_t.join();

    // 3. Signal shutdown to all queues
    for (auto& q : worker_queues_) {
        q->shutdown();
    }
    output_queue_.shutdown();

    // 4. Wait for consumers to finish
    for (auto& w : workers) w->join();
    writer_t.join();
    if (stats_t) stats_t->join();


    // 3. Collect final flow records for reporting
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

    RawPacket raw;
    while (reader.nextPacket(raw)) {
        FiveTuple tuple;
        if (quickTuple(raw, tuple)) {
            FiveTupleHash hasher;
            size_t worker_idx = hasher(tuple.canonical()) % cfg_.num_workers;
            if (!worker_queues_[worker_idx]->push(std::move(raw))) {
                 PacketPool::instance().release(raw);
                 break;
            }
        } else {
            stats_.malformed_packets.fetch_add(1);
            PacketPool::instance().release(raw);
        }
    }

    for (auto& q : worker_queues_) q->shutdown();
}

void DpiPipeline::workerThread(int worker_id) {
    auto& queue = *worker_queues_[worker_id];
    auto& tracker = *flow_trackers_[worker_id];

    while (true) {
        auto opt_raw = queue.pop();
        if (!opt_raw) break;
        RawPacket& raw = *opt_raw;

        auto t_start = std::chrono::steady_clock::now();
        stats_.total_packets.fetch_add(1);
        stats_.total_bytes.fetch_add(raw.len);

        ParsedPacket pkt;
        if (!PacketParser::parse(raw, pkt)) {
            stats_.malformed_packets.fetch_add(1);
            PacketPool::instance().release(raw);
            continue;
        }

        // Protocol stats
        if (pkt.ip_proto == proto::TCP) stats_.tcp_packets.fetch_add(1);
        else if (pkt.ip_proto == proto::UDP) stats_.udp_packets.fetch_add(1);
        else if (pkt.ip_proto == proto::ICMP) stats_.icmp_packets.fetch_add(1);

        // State update & DPI
        Flow* flow = tracker.update(pkt);
        
        // Detailed classification with TCP reassembly
        if (!flow->sni_seen && pkt.payload && pkt.payload_len > 0) {
            bool should_extract = false;
            const uint8_t* dpi_data = pkt.payload;
            size_t         dpi_len  = pkt.payload_len;

            if (pkt.has_tcp) {
                // Try to append to reassembly buffer
                if (flow->appendSegment(pkt.tcp_seq, pkt.payload, pkt.payload_len)) {
                    dpi_data = flow->reassembly_buffer.data();
                    dpi_len  = flow->reassembly_buffer.size();
                    should_extract = true;
                }
            } else if (pkt.has_udp) {
                should_extract = true;
            }

            if (should_extract) {
                auto sni = SNIExtractor::extract(dpi_data, dpi_len);
                if (sni) {
                    flow->sni = *sni;
                    flow->app_type = sniToAppType(*sni);
                    flow->sni_seen = true;
                    if (cfg_.verbose) {
                        std::cout << "[VERBOSE] extracted SNI: " << *sni << "\n";
                    }
                } else if (BitTorrentDetector::detect(dpi_data, dpi_len)) {
                    flow->app_type = AppType::BITTORRENT;
                    flow->sni_seen = true;
                    if (cfg_.verbose) {
                        std::cout << "[VERBOSE] detected BitTorrent\n";
                    }
                } else if (flow->dpi_complete) {
                    // We've seen enough bytes and still no classification
                    flow->sni_seen = true; 
                }
            }
        }
        
        // Rule evaluation
        bool blocked = flow->blocked || rules_.shouldBlock(pkt, *flow);
        if (blocked) {
            if (!flow->blocked && cfg_.verbose) {
                std::cout << "--- DPI Analysis: " << cfg_.input_file << " ---\n";
            }
            flow->blocked = true;
            stats_.blocked_packets.fetch_add(1);
            PacketPool::instance().release(raw); // Rule-blocked packets are released here
        } else {
            stats_.forwarded_packets.fetch_add(1);
            if (!cfg_.output_file.empty()) {
                output_queue_.push(std::move(raw));
            } else {
                PacketPool::instance().release(raw); // No output file, release after processing
            }
        }

        auto t_end = std::chrono::steady_clock::now();
        stats_.total_latency_ns.fetch_add(
            std::chrono::duration_cast<std::chrono::nanoseconds>(t_end - t_start).count()
        );

        // Periodic flow eviction
        if (stats_.total_packets.load() % 10000 == 0) {
            tracker.evictStale(raw.ts_sec);
        }
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
        auto opt_raw = output_queue_.pop();
        if (!opt_raw) break;
        writer.writePacket(*opt_raw);
        PacketPool::instance().release(*opt_raw); // Release after writing
    }
}

void DpiPipeline::statsThread() {
    while (workers_done_.load() < cfg_.num_workers) {
        compat::sleep_ms(1000);
        
        std::cout << "[STATS] " << std::fixed << std::setprecision(0) 
                  << stats_.throughputPps() << " pps | Latency: " 
                  << std::setprecision(2) << stats_.avgLatencyMs() << " ms | Blocks: "
                  << stats_.blocked_packets.load() << "\n";
    }
}

bool DpiPipeline::quickTuple(const RawPacket& raw, FiveTuple& out) {
    if (raw.len < 14) return false;
    const uint8_t* d = raw.data;
    uint16_t etype = (uint16_t(d[12]) << 8) | d[13];

    if (etype == proto::ETH_IPV4) {
        if (raw.len < 34) return false;
        out.setIPv4((uint32_t(d[26]) << 24) | (uint32_t(d[27]) << 16) | (uint32_t(d[28]) << 8) | d[29],
                    (uint32_t(d[30]) << 24) | (uint32_t(d[31]) << 16) | (uint32_t(d[32]) << 8) | d[33]);
        out.protocol = d[23];
        size_t ip_len = (d[14] & 0x0F) * 4;
        size_t l4_off = 14 + ip_len;
        if (raw.len < l4_off + 4) return false;
        out.src_port = (uint16_t(d[l4_off]) << 8) | d[l4_off+1];
        out.dst_port = (uint16_t(d[l4_off+2]) << 8) | d[l4_off+3];
        return true;
    } else if (etype == proto::ETH_IPV6) {
        if (raw.len < 54) return false;
        out.is_ipv6 = true;
        std::memcpy(out.src_ip, d + 14 + 8, 16);
        std::memcpy(out.dst_ip, d + 14 + 24, 16);
        out.protocol = d[14 + 6];
        // IPv6 doesn't have a fixed L4 offset if there are extension headers, 
        // but for 'quick' we assume no extensions or first extension starts at 54.
        out.src_port = (uint16_t(d[54]) << 8) | d[55];
        out.dst_port = (uint16_t(d[56]) << 8) | d[57];
        return true;
    }
    return false;
}

void DpiPipeline::printSummary() const {
    uint64_t total    = stats_.total_packets.load();
    uint64_t parsed   = total - stats_.malformed_packets.load();
    uint64_t blocked  = stats_.blocked_packets.load();
    uint64_t dropped  = stats_.dropped_packets.load();
    uint64_t forwarded = stats_.forwarded_packets.load();

    auto pct = [](uint64_t n, uint64_t d) -> double {
        return d > 0 ? 100.0 * double(n) / double(d) : 0.0;
    };

    std::cout << "\n--- NETWORK TRAFFIC ANALYSIS ENGINE ---\n";
    std::cout << "  Duration:    " << std::fixed << std::setprecision(2)
              << stats_.elapsedSec() << " s\n";
    std::cout << "  Throughput:  " << std::setprecision(0)
              << stats_.throughputPps() << " pps  /  "
              << std::setprecision(1) << stats_.throughputMBps() << " MB/s\n";
    std::cout << "  Avg Latency: " << std::setprecision(1)
              << stats_.avgLatencyUs() << " us/pkt\n";
    std::cout << "  Threads:     " << cfg_.num_workers << "\n\n";

    // Per-stage pipeline counters
    std::cout << "  Pipeline Stage Breakdown:\n";
    std::cout << "    [Reader ] " << total << " pkts read\n";
    std::cout << "    [Parser ] " << parsed << " parsed"
              << "  (" << stats_.malformed_packets.load() << " malformed, "
              << std::setprecision(1) << pct(stats_.malformed_packets.load(), total) << "%)\n";
    std::cout << "    [DPI    ] " << parsed << " inspected\n";
    std::cout << "    [Rules  ] " << parsed << " evaluated"
              << "  (" << blocked << " blocked, "
              << pct(blocked, parsed) << "%)\n";
    std::cout << "    [Drop   ] " << dropped
              << "  (queue overflow = " << pct(dropped, total) << "%)\n";
    std::cout << "    [Forward] " << forwarded << "\n";

    std::cout << "\n  Protocol Mix:  TCP " << stats_.tcp_packets.load()
              << " / UDP " << stats_.udp_packets.load()
              << " / ICMP " << stats_.icmp_packets.load() << "\n";

    // --- Top Domains (Signature Feature) ---
    std::unordered_map<std::string, uint64_t> domain_flows;
    uint64_t total_flows_with_sni = 0;
    for (const auto& f : all_flows_) {
        if (!f.sni.empty()) {
            domain_flows[f.sni] += f.pkt_count;
            ++total_flows_with_sni;
        }
    }

    if (!domain_flows.empty()) {
        std::vector<std::pair<std::string, uint64_t>> sorted_domains(
            domain_flows.begin(), domain_flows.end());
        std::sort(sorted_domains.begin(), sorted_domains.end(),
                  [](const auto& a, const auto& b){ return a.second > b.second; });

        std::cout << "\n  Top Observed Domains:\n";
        uint64_t total_domain_pkts = 0;
        for (const auto& d : sorted_domains) total_domain_pkts += d.second;

        size_t display = std::min(sorted_domains.size(), size_t(8));
        for (size_t i = 0; i < display; ++i) {
            double share = total_domain_pkts > 0
                ? 100.0 * double(sorted_domains[i].second) / double(total_domain_pkts)
                : 0.0;
            std::cout << "    " << std::left << std::setw(30) << sorted_domains[i].first
                      << std::right << std::setw(8) << sorted_domains[i].second << " pkts"
                      << "  (" << std::fixed << std::setprecision(1) << share << "%)\n";
        }
    }

    // Top Flows by Bytes
    std::vector<Flow> top = all_flows_;
    std::sort(top.begin(), top.end(), [](const Flow& a, const Flow& b){
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
    std::cout << "{\"stats\":" << stats_.toJSON() << ",\"flows\":[";
    
    std::vector<Flow> top = all_flows_;
    std::sort(top.begin(), top.end(), [](const Flow& a, const Flow& b){
        return a.byte_count > b.byte_count;
    });

    for (size_t i = 0; i < std::min(top.size(), size_t(50)); ++i) {
        std::cout << top[i].toJSON();
        if (i < std::min(top.size(), size_t(50)) - 1) std::cout << ",";
    }
    std::cout << "]}\n";
}
