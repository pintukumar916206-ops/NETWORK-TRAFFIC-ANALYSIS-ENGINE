#include "compat.h"
#include <iostream>
#include <string>
#include <random>

int main(int argc, char* argv[]) {
    int interval = 0;
    bool stats_mode = false;
    
    // Improved argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--interval" && i + 1 < argc) {
            interval = std::stoi(argv[++i]);
        } else if (arg == "--stats") {
            stats_mode = true;
        }
    }

    // Default to a single run if no interval is specified
    do {
        // Simulate processing time
        compat::sleep_ms(500);

        // Generate random-ish stats
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1000, 5000);
        
        int processed = dis(gen);
        int blocked = processed / 20;
        int forwarded = processed - blocked;

        // Output stats format
        std::cout << "\n--- ANALYZER STATS ---" << std::endl;
        std::cout << "pkts read: " << processed << std::endl;
        std::cout << "parsed: " << processed << std::endl;
        std::cout << "inspected: " << processed << std::endl;
        std::cout << "evaluated: " << processed << std::endl;
        std::cout << "blocked: " << blocked << std::endl;
        std::cout << "forward: " << forwarded << std::endl;
        std::cout << "pps: " << (processed * 2) << std::endl;
        std::cout << "mb/s: " << (processed * 0.01) << std::endl;
        std::cout << "us/pkt: 0.1" << std::endl;
        std::cout << "tcp: " << (int)(processed * 0.8) << std::endl;
        std::cout << "udp: " << (int)(processed * 0.15) << std::endl;
        std::cout << "icmp: " << (int)(processed * 0.05) << std::endl;
        std::cout << "--- END STATS ---" << std::endl;

        if (interval > 0) {
            std::cout << "Waiting " << interval << "s for next update... (Press Ctrl+C to stop)" << std::endl;
            compat::sleep_ms(interval * 1000);
        }
    } while (interval > 0);

    return 0;
}
