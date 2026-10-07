#ifndef FLOWRAY_EXPORT_H
#define FLOWRAY_EXPORT_H

#include <cstdint>
#include <string>
#include <vector>

#include "../ebpf/ebpf_monitor.h"
#include "data.h"

status_msg validate_export_path(const std::string& path);
status_msg validate_exs_file (const std::string& path);

// status_msg export_ebpf_json(
//     const std::string& path,
//     const std::vector<std::uint32_t>& pids,
//     const std::string& proc_name,
//     const std::vector<ebpf_traffic>& traffic,
//     const std::vector<event>& events);

status_msg export_socket_json(
    const std::string& path,
    const std::vector<std::uint32_t>& pids,
    const std::string& proc_name,
    const std::vector<ProcessInfo>& process,
    const std::vector<LiveSocket>& sockets);

#endif //FLOWRAY_EXPORT_H
