#pragma once

#include "types.h"
#include "lpm_trie.h"
#include "aho_corasick.h"
#include <string>
#include <unordered_set>
#include <vector>
#include <atomic>
#include <cstdint>

// Engine for matching and blocking traffic based on IP, domain, app, and port rules.
class RuleEngine {
public:
  RuleEngine() = default;

  // Rule loading (call before run(), single-threaded)
  void addBlockIP(const std::string &cidr_or_ip);
  void addBlockDomain(const std::string &substring);
  void addBlockApp(AppType app);
  void addBlockPort(uint16_t port);

  // Load rules from a JSON config file.
  // Format: {"rules": [{"type": "domain|ip|port", "value": "..."}]}
  // Returns number of rules loaded, or -1 on error.
  int loadFromFile(const std::string &path);

  // ── Hot-path evaluation (thread-safe read-only) ─────────────────
  // Returns true if the packet/flow should be dropped.
  bool shouldBlock(const ParsedPacket &pkt, const Flow &flow) const noexcept;

  // Finalize rules after all additions
  void buildAutomata() { if (!domain_matcher_.empty()) domain_matcher_.build(); }

  bool hasRules() const noexcept {
    return has_v4_rules_ || has_v6_rules_ || !domain_matcher_.empty() ||
           !blocked_apps_.empty() || !blocked_ports_.empty();
  }

  // ── Diagnostics ────────────────────────────────────────────────
  void printRules() const;

private:
  LpmTrie v4_trie_;
  LpmTrie v6_trie_;
  AhoCorasick domain_matcher_;
  bool has_v4_rules_ = false;
  bool has_v6_rules_ = false;
  std::unordered_set<uint16_t> blocked_ports_;
  std::unordered_set<uint8_t> blocked_apps_; // cast AppType → uint8_t

  void parseAndAddIP(const std::string &token);
};
