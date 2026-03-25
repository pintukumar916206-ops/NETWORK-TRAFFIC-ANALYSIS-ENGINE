#pragma once

#include "types.h"
#include <vector>
#include <atomic>
#include "compat.h"

class PacketPool {
public:
    static constexpr uint32_t POOL_SIZE      = 16384;
    static constexpr size_t   PACKET_MAX_LEN = 2048;

    static PacketPool& instance() {
        static PacketPool pool;
        return pool;
    }

    RawPacket lease();
    void      release(RawPacket& pkt);

    size_t available() const noexcept { return available_count_.load(); }

private:
    PacketPool();
    ~PacketPool();

    PacketPool(const PacketPool&)            = delete;
    PacketPool& operator=(const PacketPool&) = delete;

    uint8_t*  slab_ = nullptr;
    std::vector<uint32_t>   free_indices_;
    mutable compat::mutex   stack_mu_;
    std::atomic<size_t>     available_count_{0};
};
