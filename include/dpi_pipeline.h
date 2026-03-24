#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "types.h"
#include "packet_source.h"
#include "pcap_writer.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "flow_tracker.h"
#include "rule_engine.h"
#include "concurrency/lock_free_queue.h"
#include "compat.h"

// High-level pipeline orchestrator.
class DpiPipeline {
public:
  struct Config {
    std::string input_file;
    std::string output_file;
    int num_workers = 4;
    size_t queue_capacity = 65536;
    bool print_stats = true;
    bool verbose = false;
    bool live_stats = false;
    bool json_output = false;
    bool loop = false;
    int delay_ms = 1000;
  };

  explicit DpiPipeline(Config cfg);

  void addBlockIP(const std::string &ip);
  void addBlockDomain(const std::string &domain);
  void addBlockApp(const std::string &app_name);
  void addBlockPort(uint16_t port);
  void loadRules(const std::string &path);

  void run();
  void printSummary() const;
  void printSummaryJson() const;
  const Stats &stats() const noexcept { return stats_; }

private:
  void readerThread();
  void workerThread(int worker_id);
  void writerThread();
  void statsThread();

  static bool quickTuple(const RawPacket &raw, FiveTuple &out);

  Config cfg_;
  Stats stats_;
  RuleEngine rules_;

  std::vector<std::unique_ptr<LockFreeQueue<RawPacket>>> worker_queues_;
  std::vector<std::unique_ptr<FlowTracker>> flow_trackers_;

  LockFreeQueue<RawPacket> output_queue_;

  std::atomic<int> workers_done_{0};
  mutable std::vector<Flow> all_flows_;
};
