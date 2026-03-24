#include "dpi_pipeline.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

void printHelp() {
  std::cout << "NETWORK TRAFFIC ANALYSIS ENGINE\n"
            << "Usage: traffic_engine [options]\n\n"
            << "Options:\n"
            << "  --input <file>       Input PCAP file (required)\n"
            << "  --output <file>      Filtered PCAP output file\n"
            << "  --threads <N>        Number of worker threads (default: 4)\n"
            << "  --stats              Print real-time processing statistics\n"
            << "  --benchmark          Run 3 passes and print averaged throughput results\n"
            << "  --rules <file>       Load blocking rules from a JSON config file\n"
            << "  --verbose            Print detailed per-packet logs\n"
            << "  --block-ip <IP>      Block traffic to/from this IP or CIDR\n"
            << "  --block-domain <str> Block traffic matching this domain substring\n"
            << "  --block-app <app>    Block a specific application (youtube, netflix, etc.)\n"
            << "  --block-port <port>  Block a specific destination port\n"
            << "  --loop               Continuous looping\n"
            << "  --delay <ms>         Delay between loops in ms (default: 1000)\n"
            << "  --help               Display this help message\n\n"
            << "Example:\n"
            << "  traffic_engine --input capture.pcap --threads 4 --benchmark\n"
            << "  traffic_engine --input capture.pcap --rules rules.json\n\n";
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printHelp();
    return 1;
  }

  DpiPipeline::Config cfg;
  std::vector<std::string> block_ips;
  std::vector<std::string> block_domains;
  std::vector<std::string> block_apps;
  std::vector<uint16_t> block_ports;

  std::string rules_file;
  bool benchmark_mode = false;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help") {
      printHelp();
      return 0;
    } else if (arg == "--input" && i + 1 < argc) {
      cfg.input_file = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      cfg.output_file = argv[++i];
    } else if (arg == "--threads" && i + 1 < argc) {
      cfg.num_workers = std::stoi(argv[++i]);
    } else if (arg == "--stats") {
      cfg.live_stats = true;
    } else if (arg == "--json") {
      cfg.json_output = true;
    } else if (arg == "--verbose") {
      cfg.verbose = true;
    } else if (arg == "--benchmark") {
      benchmark_mode = true;
    } else if (arg == "--rules" && i + 1 < argc) {
      rules_file = argv[++i];
    } else if (arg == "--block-ip" && i + 1 < argc) {
      block_ips.push_back(argv[++i]);
    } else if (arg == "--block-domain" && i + 1 < argc) {
      block_domains.push_back(argv[++i]);
    } else if (arg == "--block-app" && i + 1 < argc) {
      block_apps.push_back(argv[++i]);
    } else if (arg == "--loop") {
      cfg.loop = true;
    } else if (arg == "--delay" && i + 1 < argc) {
      cfg.delay_ms = std::stoi(argv[++i]);
    } else if (arg == "--block-port" && i + 1 < argc) {
      block_ports.push_back(std::stoi(argv[++i]));
    }
  }

  if (cfg.input_file.empty()) {
    std::cerr << "Error: --input <file> is required.\n";
    return 1;
  }

  // Benchmark mode: run 3 passes, average the results
  if (benchmark_mode) {
    const int PASSES = 3;
    double total_pps = 0, total_mbps = 0, total_us = 0;
    std::cout << "[BENCHMARK] Running " << PASSES << " passes on "
              << cfg.input_file << "  (" << cfg.num_workers << " threads)\n\n";
    for (int pass = 1; pass <= PASSES; ++pass) {
      DpiPipeline pipeline(cfg);
      if (!rules_file.empty()) pipeline.loadRules(rules_file);
      for (const auto& ip : block_ips)    pipeline.addBlockIP(ip);
      for (const auto& d  : block_domains) pipeline.addBlockDomain(d);
      for (const auto& a  : block_apps)    pipeline.addBlockApp(a);
      for (const auto& p  : block_ports)   pipeline.addBlockPort(p);
      pipeline.run();
      const Stats& s = pipeline.stats();
      double pps = s.throughputPps(), mbps = s.throughputMBps(), us = s.avgLatencyUs();
      std::cout << "  Pass " << pass << ":  "
                << std::fixed << std::setprecision(0) << pps << " pps  /  "
                << std::setprecision(1) << mbps << " MB/s  /  "
                << std::setprecision(1) << us << " us avg latency\n";
      total_pps += pps; total_mbps += mbps; total_us += us;
    }
    std::cout << "\n  Averaged over " << PASSES << " passes:\n";
    std::cout << "    Throughput:  " << std::fixed << std::setprecision(0)
              << total_pps / PASSES << " pps  /  "
              << std::setprecision(1) << total_mbps / PASSES << " MB/s\n";
    std::cout << "    Avg Latency: " << total_us / PASSES << " us/pkt\n";
    std::cout << "    Threads:     " << cfg.num_workers << "\n";
    return 0;
  }

  do {
    DpiPipeline pipeline(cfg);
    if (!rules_file.empty()) pipeline.loadRules(rules_file);
    for (const auto& ip : block_ips)    pipeline.addBlockIP(ip);
    for (const auto& d  : block_domains) pipeline.addBlockDomain(d);
    for (const auto& a  : block_apps)    pipeline.addBlockApp(a);
    for (const auto& p  : block_ports)   pipeline.addBlockPort(p);

    pipeline.run();
    if (cfg.json_output) {
      pipeline.printSummaryJson();
    } else {
      pipeline.printSummary();
    }
    if (cfg.loop) {
      std::cout << "\n[RESTARTING LOOP IN " << cfg.delay_ms << "ms...]\n";
      compat::sleep_ms(cfg.delay_ms);
    }
  } while (cfg.loop);

  return 0;
}
