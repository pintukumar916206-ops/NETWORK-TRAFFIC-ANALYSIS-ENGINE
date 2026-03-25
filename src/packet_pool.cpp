#include "packet_pool.h"
#include <cstdlib>

PacketPool::PacketPool() {
    size_t total = size_t(POOL_SIZE) * PACKET_MAX_LEN;
    slab_ = static_cast<uint8_t*>(malloc(total));
    if (!slab_) return;

    free_indices_.reserve(POOL_SIZE);
    for (uint32_t i = 0; i < POOL_SIZE; ++i)
        free_indices_.push_back(i);

    available_count_.store(POOL_SIZE);
}

PacketPool::~PacketPool() {
    free(slab_);
}

RawPacket PacketPool::lease() {
    compat::lock_guard<compat::mutex> lk(stack_mu_);
    if (free_indices_.empty()) return {};

    uint32_t slot = free_indices_.back();
    free_indices_.pop_back();
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

    {
        compat::lock_guard<compat::mutex> lk(stack_mu_);
        free_indices_.push_back(slot);
    }

    available_count_.fetch_add(1);
    pkt.data      = nullptr;
    pkt.len       = 0;
    pkt._pool_ref = nullptr;
}
