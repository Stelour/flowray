#include "../headers/pid.h"
#include "../headers/output.h"
#include "../headers/socket.h"
#include "../headers/proc_name.h"
#include "../headers/output_ftxui.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <array>
#include <algorithm>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <cstdlib>

static bool check_pid_is_correct(const std::string& dir_path) {
    return std::filesystem::is_directory(dir_path);
}

static void find_socket_inodes(
    const std::string& dir_path,
    std::unordered_map<std::uint32_t, std::set<std::uint32_t>>& socket_inodes,
    std::uint32_t proc_pid, SocketFdMap* socket_fds = nullptr) {
    try {
        for (const auto& entry : std::filesystem::directory_iterator(dir_path + "/fd")) {
            std::error_code ec;
            std::string cur_fd = std::filesystem::read_symlink(entry.path(), ec);
            if (ec) {
                continue;
            }
            if (cur_fd.starts_with("socket:[")) {
                std::uint32_t ind = std::stoul(cur_fd.substr(cur_fd.find('[') + 1, cur_fd.find(']') - cur_fd.find('[') - 1));
                // socket_inodes.insert(std::stoul(
                //     cur_fd.substr(cur_fd.find('[') + 1, cur_fd.find(']') - cur_fd.find('[') - 1)));
                socket_inodes[ind].insert(proc_pid);
                if (socket_fds) {
                    int fd;
                    try {
                        fd = std::stoi(entry.path().filename().string());
                    }
                    catch (...) {
                        continue;
                    }
                    (*socket_fds)[ind].push_back({.pid = proc_pid,.fd = fd});
                }
            }
        }
    } catch(const std::filesystem::filesystem_error&) {
        return;
    }
}

status_msg get_proc_sockets(
    const std::vector<uint32_t>& pids,
    bool pid_tree,
    std::vector<ProcessInfo>& processes,
    std::vector<SocketInfo>& sockets, SocketFdMap* socket_fds = nullptr
    ) {
    processes.clear();
    sockets.clear();
    // std::vector<std::uint32_t> procs_pid = pids | std::ranges::to<std::vector>();
    std::vector<std::uint32_t> procs_pid = pids;
    for (auto pid : pids) {
        std::string dir_path = "/proc/" + std::to_string(pid);

        if (!check_pid_is_correct(dir_path)) {
            std::cerr << "ERROR: incorrect PID " << pid << std::endl;
            return status_msg::error;
        }
    }

    if (pid_tree) {
        for (auto pid : pids) {
            push_pid_tree(pid, procs_pid);
        }
        std::sort(procs_pid.begin(), procs_pid.end());
        procs_pid.erase(
            std::unique(procs_pid.begin(), procs_pid.end()),
            procs_pid.end()
        );
    }

    // std::unordered_set<std::uint32_t> socket_inodes = {};
    std::unordered_map<std::uint32_t, std::set<std::uint32_t>> socket_inodes;
    for (auto& proc_pid : procs_pid) {
        find_socket_inodes("/proc/" + std::to_string(proc_pid), socket_inodes, proc_pid, socket_fds);
    }

    for (auto pid : procs_pid) {
        std::ifstream file("/proc/" + std::to_string(pid) + "/comm");
        if (!file) {
            continue;
        }
        std::string name;
        std::getline(file, name);
        processes.push_back({pid,name});
    }

    // req to socket
    const std::array<DiagQuery, 4> queries{{
        {AF_INET,  IPPROTO_TCP},
        {AF_INET,  IPPROTO_UDP},
        {AF_INET6, IPPROTO_TCP},
        {AF_INET6, IPPROTO_UDP}
    }};


    for (const auto& query : queries) {
        if (socket_req(socket_inodes, sockets, query) != status_msg::success) {
            return status_msg::error;
        }
    }
    return status_msg::success;
}

static void update_live_state(std::vector<LiveSocket>& live_sockets, const std::vector<SocketInfo>& new_sockets) {
    for (auto& socket : live_sockets) {
        socket.active = false;
    }

    for (const auto& sock : new_sockets) {
        bool flag = false;

        for (auto& live_socket : live_sockets) {
            if (live_socket.socket.inode == sock.inode) {
                live_socket.socket = sock;
                live_socket.last_seen = std::chrono::system_clock::now();
                live_socket.active = true;

                flag = true;
                break;
            }
        }


        if (!flag) {
            LiveSocket new_socket;

            new_socket.socket = sock;
            new_socket.first_seen = std::chrono::system_clock::now();
            new_socket.last_seen = std::chrono::system_clock::now();
            new_socket.active = true;

            live_sockets.push_back(new_socket);
        }
    }
}

status_msg update_live_data(
    std::vector<std::uint32_t>& pids,
    bool pid_tree, const std::string& proc_name,
    std::vector<ProcessInfo>& processes,
    std::vector<LiveSocket>& live_sockets) {
    if(!proc_name.empty()) {
        pids = find_pids_by_name(proc_name);
    }

    std::vector<ProcessInfo> new_processes;
    std::vector<SocketInfo> new_sockets;

    if (get_proc_sockets(pids, pid_tree, new_processes, new_sockets) != status_msg::success) {
        return status_msg::error;
    }

    update_live_state(live_sockets, new_sockets);

    // print_socket_diff(new_sockets, sockets, pid_detail);
    //
    processes = std::move(new_processes);
    // sockets = std::move(new_sockets);
    return status_msg::success;
}

static status_msg start_live_mode(
    std::vector<std::uint32_t> pids,
    bool pid_tree, bool pid_detail, const std::string& proc_name
    ) {
    std::vector<LiveSocket> live_sockets;
    std::vector<ProcessInfo> processes;

    while (true) {
        if (update_live_data(pids, pid_tree, proc_name, processes, live_sockets) != status_msg::success) {
            continue;
        }

        std::cout << "\033[2J\033[H" << std::flush;
        std::cout << "FlowRay live mode" << std::endl << std::endl;
        print_process_info(processes);
        print_live_table(live_sockets, pid_detail);

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

status_msg start_pid(const std::vector<std::uint32_t>& pids, bool pid_tree, bool pid_detail, bool proc_live, const std::string& proc_name, bool live_print) {
    if (proc_live) {
        if (live_print) {
            return start_live_mode(pids, pid_tree, pid_detail, proc_name);
        }
        return output_table_socket_live(pids, pid_tree, pid_detail, proc_name);
    }

    std::vector<ProcessInfo> processes;
    std::vector<SocketInfo> sockets;
    if (get_proc_sockets(pids, pid_tree, processes, sockets) != status_msg::success) {
        std::cerr << "ERROR: failed to get proc_sockets" << std::endl;
        return status_msg::error;
    }

    std::system("clear");
    print_process_info(processes);
    print_socket_info(sockets, pid_detail);

    return status_msg::success;
}
