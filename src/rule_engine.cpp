#include "rule_engine.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>

static uint32_t dotted_to_u32(const std::string& s) {
    unsigned o[4];
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &o[0], &o[1], &o[2], &o[3]) != 4)
        throw std::invalid_argument("Bad IP: " + s);
    for (int i = 0; i < 4; ++i)
        if (o[i] > 255) throw std::invalid_argument("IP octet out of range: " + s);
    return (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
}

static void u32_to_bytes(uint32_t ip, uint8_t out[4]) {
    out[0] = uint8_t(ip >> 24);
    out[1] = uint8_t(ip >> 16);
    out[2] = uint8_t(ip >> 8);
    out[3] = uint8_t(ip);
}

void RuleEngine::addBlockIP(const std::string& token) {
    if (token.find(':') != std::string::npos) {
        uint8_t v6[16] = {};
        v6_trie_.insert(v6, 128);
        has_v6_rules_ = true;
        return;
    }

    size_t slash = token.find('/');
    std::string host  = slash != std::string::npos ? token.substr(0, slash) : token;
    int         bits  = slash != std::string::npos ? std::stoi(token.substr(slash + 1)) : 32;

    uint32_t ip = dotted_to_u32(host);
    uint8_t  b[4];
    u32_to_bytes(ip, b);
    v4_trie_.insert(b, bits);
    has_v4_rules_ = true;
}

void RuleEngine::addBlockDomain(const std::string& pat) {
    std::string lower = pat;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    domain_matcher_.addPattern(lower);
}

void RuleEngine::addBlockApp(AppType app)   { blocked_apps_.insert(static_cast<uint8_t>(app)); }
void RuleEngine::addBlockPort(uint16_t port) { blocked_ports_.insert(port); }

bool RuleEngine::shouldBlock(const ParsedPacket& pkt, const Flow& flow) const noexcept {
    auto check_ip4 = [&]() -> bool {
        if (!has_v4_rules_) return false;
        uint8_t src[4], dst[4];
        u32_to_bytes(pkt.src_ip, src);
        u32_to_bytes(pkt.dst_ip, dst);
        return v4_trie_.match(src, 32) || v4_trie_.match(dst, 32);
    };

    auto check_ip6 = [&]() -> bool {
        if (!has_v6_rules_) return false;
        return v6_trie_.match(pkt.src_ip6, 128) || v6_trie_.match(pkt.dst_ip6, 128);
    };

    if (pkt.is_ipv6 ? check_ip6() : check_ip4()) return true;

    if (!blocked_ports_.empty() && blocked_ports_.count(pkt.dst_port))    return true;
    if (!blocked_apps_.empty()  && blocked_apps_.count(
            static_cast<uint8_t>(flow.app_type)))                         return true;

    if (!flow.sni.empty() && !domain_matcher_.empty())
        if (domain_matcher_.match(flow.sni)) return true;

    return false;
}

void RuleEngine::printRules() const {
    if (has_v4_rules_)          std::cout << "  [RULE] IPv4 LPM active\n";
    if (has_v6_rules_)          std::cout << "  [RULE] IPv6 LPM active\n";
    if (!domain_matcher_.empty()) std::cout << "  [RULE] Domain pattern matcher active\n";
    for (uint16_t p : blocked_ports_)
        std::cout << "  [RULE] Block port: " << p << "\n";
    for (uint8_t  a : blocked_apps_)
        std::cout << "  [RULE] Block app:  " << appTypeToString(static_cast<AppType>(a)) << "\n";
}

int RuleEngine::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[RULES] Cannot open rule file: " << path << "\n";
        return -1;
    }

    std::string body((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());

    auto field = [&](const std::string& text, const std::string& key) -> std::string {
        std::string needle = "\"" + key + "\"";
        size_t p = text.find(needle);
        if (p == std::string::npos) return {};
        p = text.find(':', p);
        if (p == std::string::npos) return {};
        while (++p < text.size() && (text[p] == ' ' || text[p] == '\t')) {}
        if (p >= text.size() || text[p] != '"') return {};
        size_t start = p + 1;
        size_t end   = text.find('"', start);
        return end != std::string::npos ? text.substr(start, end - start) : std::string{};
    };

    int loaded = 0;
    size_t cur = 0;

    while (cur < body.size()) {
        size_t open  = body.find('{', cur + 1);
        if (open == std::string::npos) break;
        size_t close = body.find('}', open);
        if (close == std::string::npos) break;

        std::string blk   = body.substr(open, close - open + 1);
        cur = close;

        std::string type  = field(blk, "type");
        std::string value = field(blk, "value");
        if (type.empty() || value.empty()) continue;

        if (type == "domain") {
            addBlockDomain(value);
        } else if (type == "ip") {
            addBlockIP(value);
        } else if (type == "port") {
            try { addBlockPort(static_cast<uint16_t>(std::stoi(value))); }
            catch (...) {
                std::cerr << "[RULES] Invalid port: " << value << "\n";
                continue;
            }
        } else if (type == "app") {
            static const struct { const char* name; AppType type; } apps[] = {
                { "youtube",    AppType::YOUTUBE    },
                { "facebook",   AppType::FACEBOOK   },
                { "netflix",    AppType::NETFLIX    },
                { "bittorrent", AppType::BITTORRENT },
            };
            bool found = false;
            for (auto& a : apps) {
                if (value == a.name) { addBlockApp(a.type); found = true; break; }
            }
            if (!found) {
                std::cerr << "[RULES] Unknown app: " << value << "\n";
                continue;
            }
        } else {
            std::cerr << "[RULES] Unknown rule type: " << type << "\n";
            continue;
        }
        ++loaded;
    }

    std::cout << "[RULES] Loaded " << loaded << " rules from " << path << "\n";
    return loaded;
}
