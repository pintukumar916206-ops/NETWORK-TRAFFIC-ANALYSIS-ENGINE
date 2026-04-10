#include "compat.h"
#include "rule_engine.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <nlohmann/json.hpp>
#include "utils/logger.h"

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
    size_t slash = token.find('/');
    std::string host = slash != std::string::npos ? token.substr(0, slash) : token;
    
    if (token.find(':') != std::string::npos) {
        int bits = slash != std::string::npos ? std::stoi(token.substr(slash + 1)) : 128;
        uint8_t v6[16] = {};
        
        bool parsed = false;
#if defined(_WIN32)
        struct sockaddr_in6 sa;
        int size = sizeof(sa);
        if (WSAStringToAddressA((LPSTR)host.c_str(), AF_INET6, NULL, (struct sockaddr*)&sa, &size) == 0) {
            memcpy(v6, &sa.sin6_addr, 16);
            parsed = true;
        }
#else
        if (inet_pton(AF_INET6, host.c_str(), v6) == 1) {
            parsed = true;
        }
#endif

        if (parsed) {
            v6_trie_.insert(v6, bits);
            has_v6_rules_ = true;
        } else {
            LOG_ERROR("Invalid IPv6 Address: " + host);
        }
        return;
    }

    int bits = slash != std::string::npos ? std::stoi(token.substr(slash + 1)) : 32;

    try {
        uint32_t ip = dotted_to_u32(host);
        uint8_t  b[4];
        u32_to_bytes(ip, b);
        v4_trie_.insert(b, bits);
        has_v4_rules_ = true;
    } catch (const std::exception& e) {
        LOG_ERROR(std::string("Skipping invalid IP rule: ") + token + " (" + e.what() + ")");
    }
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
        LOG_ERROR("[RULES] Cannot open rule file: " + path);
        return -1;
    }

    nlohmann::json j;
    try {
        file >> j;
    } catch (const nlohmann::json::parse_error& e) {
        LOG_ERROR(std::string("[RULES] JSON parse error in ") + path + ": " + e.what());
        return -1;
    }

    if (!j.contains("rules") || !j["rules"].is_array()) {
        LOG_ERROR("[RULES] Invalid JSON format: missing 'rules' array");
        return -1;
    }

    int loaded = 0;
    for (const auto& rule : j["rules"]) {
        if (!rule.contains("type") || !rule.contains("value")) continue;
        
        std::string type = rule["type"].get<std::string>();
        std::string value;
        if (rule["value"].is_number()) {
            value = std::to_string(rule["value"].get<long long>());
        } else if (rule["value"].is_string()) {
            value = rule["value"].get<std::string>();
        } else {
            LOG_ERROR("[RULES] Unsupported value type for rule: " + type);
            continue;
        }

        if (value.length() > 256) {
            LOG_ERROR("[RULES] Value too long for rule: " + type);
            continue;
        }

        if (type == "domain") {
            addBlockDomain(value);
        } else if (type == "ip") {
            addBlockIP(value);
        } else if (type == "port") {
            try { addBlockPort(static_cast<uint16_t>(std::stoi(value))); }
            catch (...) {
                LOG_ERROR("[RULES] Invalid port: " + value);
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
                LOG_ERROR("[RULES] Unknown app: " + value);
                continue;
            }
        } else {
            LOG_ERROR("[RULES] Unknown rule type: " + type);
            continue;
        }
        ++loaded;
    }

    LOG_INFO(std::string("[RULES] Loaded ") + std::to_string(loaded) + " rules from " + path);
    return loaded;
}
