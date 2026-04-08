#include "packet_pool.h"
#include <cstdlib>
#include "utils/logger.h"

constexpr uint32_t PacketPool::POOL_SIZE;
constexpr size_t   PacketPool::PACKET_MAX_LEN;

PacketPool::PacketPool() {
    size_t total = size_t(POOL_SIZE) * PACKET_MAX_LEN;
    slab_ = static_cast<uint8_t*>(malloc(total));
    if (!slab_) {
        LOG_ERROR("Failed to allocate packet pool slab!");
        return;
    }

    free_indices_ = std::make_unique<LockFreeQueue<uint32_t>>(POOL_SIZE);
    in_use_ = std::make_unique<std::atomic<bool>[]>(POOL_SIZE);

    for (uint32_t i = 0; i < POOL_SIZE; ++i) {
        in_use_[i].store(false, std::memory_order_relaxed);
        free_indices_->push(uint32_t(i));
    }

    available_count_.store(POOL_SIZE);
}

PacketPool::~PacketPool() {
    free(slab_);
}

RawPacket PacketPool::lease() {
    auto opt_slot = free_indices_->pop();
    if (!opt_slot) return {};

    uint32_t slot = *opt_slot;

    bool expected = false;
    if (!in_use_[slot].compare_exchange_strong(expected, true)) {
        LOG_ERROR("Double lease detected for slot " + std::to_string(slot));
        return {};
    }

    available_count_.fetch_sub(1);

    RawPacket pkt;
    pkt.data      = slab_ + size_t(slot) * PACKET_MAX_LEN;
    pkt.len       = 0;
    pkt._pool_ref = reinterpret_cast<void*>(static_cast<uintptr_t>(slot));
    return pkt;
}

void PacketPool::release(RawPacket& pkt) {
    if (!pkt.data || !pkt._pool_ref) return;

    uint32_t slot = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(pkt._pool_ref));

    if (slot >= POOL_SIZE) {
        LOG_ERROR("Invalid slot ID in packet release!");
        return;
    }

    bool expected = true;
    if (!in_use_[slot].compare_exchange_strong(expected, false)) {
        LOG_ERROR("Double free detected for slot " + std::to_string(slot));
        return;
    }

    free_indices_->push(std::move(slot));
    available_count_.fetch_add(1);

    pkt.data      = nullptr;
    pkt.len       = 0;
    pkt._pool_ref = nullptr;
}
