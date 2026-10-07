#include "../headers/export.h"
#include "../headers/supp_funcs.h"

#include <nlohmann/json.hpp>
#include <chrono>
#include <fstream>
#include <netinet/in.h>
#include <sys/socket.h>

using json = nlohmann::json;

static std::int64_t time_to_ms(const std::chrono::system_clock::time_point& time) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count();
}

status_msg validate_export_path(const std::string& path) {
    if (path.empty()) {
        return status_msg::error;
    }

    std::filesystem::path export_path(path);
    if (export_path.has_parent_path()) {
        const auto parent = export_path.parent_path();
        if (!std::filesystem::exists(parent)) {
            return status_msg::error;
        }
        if (!std::filesystem::is_directory(parent)) {
            return status_msg::error;
        }
    }

    return status_msg::success;
}

status_msg validate_exs_file (const std::string& path) {
    std::filesystem::path export_path(path);
    if (export_path.extension() != ".json") {
        return status_msg::error;
    }
    return status_msg::success;
}

// status_msg export_ebpf_json(
//     const std::string& path,
//     const std::vector<std::uint32_t>& pids,
//     const std::string& proc_name,
//     const std::vector<ebpf_traffic>& traffic,
//     const std::vector<event>& events) {
//
// }

status_msg export_socket_json(
    const std::string& path,
    const std::vector<std::uint32_t>& pids,
    const std::string& proc_name,
    const std::vector<ProcessInfo>& process,
    const std::vector<LiveSocket>& sockets) {
    json j;
    j["backend"] = "socket";
    j["target"] = {
        {"name", proc_name},
        {"pids", pids},
    };

    j["processes"] = json::array();
    for (const auto& proc : process) {
        j["processes"].push_back({{"pid", proc.pid}, {"name", proc.name}});
    }

    std::uint32_t act = 0;
    for (const auto& sock : sockets) {
        if (sock.active) {
            act++;
        }
    }

    j["summaries"] = {
        {"sockets", sockets.size()},
        {"active", act},
        {"inactive", sockets.size() - act}
    };

    j["sockets"] = json::array();

    for (const auto& live : sockets) {
        const auto& sock = live.socket;
        json row = {
            {"protocol", protocol_to_string(sock.protocol)},
            {"family", protocol_to_string(sock.protocol)},
            {"local_address", sock.local_ip},
            {"local_port", sock.local_port},
            {"remote_address", sock.remote_ip},
            {"remote_port", sock.remote_port},
            {"active", live.active},
            {"first_seen", time_to_ms(live.first_seen)},
            {"last_seen", time_to_ms(live.last_seen)},
            {"lifetime_ms", std::chrono::duration_cast<std::chrono::milliseconds>(live.last_seen - live.first_seen).count()},
            {"inode", sock.inode},
        };
        if (sock.protocol == IPPROTO_TCP && live.active) {
            row["state"] = state_to_string(sock.state);
        } else {
            row["state"] = nullptr;
        }

        row["pids"] = json::array();
        for (auto pid : sock.pids) {
            row["pids"].push_back(pid);
        }

        j["sockets"].push_back(std::move(row));
    }

    std::ofstream out_file(path);

    if (!out_file.is_open()) {
        return status_msg::error;
    }

    out_file << std::setw(2) << j;

    return status_msg::success;
}