#ifndef FLOWRAY_EBPF_MONITOR_H
#define FLOWRAY_EBPF_MONITOR_H

#include "ebpf.h"

#include <cstdint>
#include <string>
#include <vector>

struct dns_query {
    std::uint32_t pid{};
    std::string domain;
    std::uint16_t type{};
};

struct ebpf_monitor;

struct ebpf_traffic {
    flow_key key{};
    flow_metrics metrics{};
};

enum class ebpf_step {
    updated,
    stopped,
    error
};

ebpf_monitor* ebpf_open(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree, std::uint64_t ring_buf_size);

ebpf_step ebpf_get_step(ebpf_monitor* monitor, std::vector<event>& events, std::vector<ebpf_traffic>& traffics,
    bool* traffic_updated = nullptr, std::vector<dns_query>* dns = nullptr);

void ebpf_close(ebpf_monitor* monitor);

int ebpf_start(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree,
    std::uint64_t ring_buf_size, const std::string& path);

#endif //FLOWRAY_EBPF_MONITOR_H
