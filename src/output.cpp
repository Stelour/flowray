#include "../headers/output.h"
#include "../headers/supp_funcs.h"

#include <iostream>
#include <netinet/in.h>
#include <string>
#include <iomanip>
#include <chrono>

void print_process_info(const std::vector<ProcessInfo>& processes) {
    std::cout << "Processes (" << processes.size() << ")" << std::endl;
    for (const auto& process : processes) {
        std::cout << "\t" << process.name << "[" << process.pid <<  "]" << std::endl;
    }
    std::cout << std::endl;
}

void print_socket_info(const std::vector<SocketInfo>& sockets, bool detail) {
    std::cout << "Sockets: " << sockets.size() << std::endl << std::endl;

    std::cout << std::left
    << std::setw(11) << "PROTOCOL |"
    << std::setw(10) << "FAMILY |"
    << std::setw(28) << "LOCAL"
    << std::setw(28) << "REMOTE"
    << std::setw(15) << "STATE";
    if (detail) {
        std::cout << std::setw(12) << "PIDS" << std::setw(12) << "INODE";
    }
    std::cout << std::endl << std::endl;

    for (const auto& socket : sockets) {
        std::cout << std::left
        << std::setw(11) << protocol_to_string(socket.protocol)
        << std::setw(10) << family_to_string(socket.family)
        << std::setw(28) << socket.local_ip + ":" + std::to_string(socket.local_port)
        << std::setw(28) << socket.remote_ip + ":" + std::to_string(socket.remote_port);
        if (socket.protocol == IPPROTO_TCP) {
            std::cout << std::setw(15) << state_to_string(socket.state);
        } else {
            std::cout << std::setw(15) << "-";
        }
        if (detail) {
            std::string pids;
            for (const auto pid : socket.pids) {
                if (!pids.empty()) {
                    pids += ',';
                }
                pids += std::to_string(pid);
            }
            std::cout << std::setw(12) << pids << std::setw(12) << socket.inode;
        }
        std::cout << std::endl;
    }
}

static std::string format_time(const std::chrono::system_clock::time_point& time) {
    auto t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%H:%M:%S");
    return oss.str();
}

static std::string format_duration(const std::chrono::system_clock::duration& duration) {
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();

    int hours = seconds / 3600;
    int minutes = (seconds % 3600) / 60;
    int secs = seconds % 60;

    std::ostringstream oss;

    oss << std::setfill('0')
        << std::setw(2) << hours << ":"
        << std::setw(2) << minutes << ":"
        << std::setw(2) << secs;

    return oss.str();
}

static void print_live_socket_info(const LiveSocket& live_socket, bool detail) {
    const auto& socket = live_socket.socket;

    std::cout << std::left
    << std::setw(11) << protocol_to_string(socket.protocol)
    << std::setw(10) << family_to_string(socket.family)
    << std::setw(28) << socket.local_ip + ":" + std::to_string(socket.local_port)
    << std::setw(28) << socket.remote_ip + ":" + std::to_string(socket.remote_port);

    if (live_socket.active) {
        if (socket.protocol == IPPROTO_TCP) {
            std::cout << std::setw(15) << state_to_string(socket.state);
        } else {
            std::cout << std::setw(15) << "-";
        }
        std::cout << std::setw(13) << format_time(live_socket.first_seen);
    } else {
        std::cout << std::setw(13) << format_time(live_socket.last_seen);
    }

    std::cout << std::setw(12) << format_duration(live_socket.last_seen - live_socket.first_seen);

    if (detail) {
        std::string pids;
        for (const auto pid : socket.pids) {
            if (!pids.empty()) {
                pids += ',';
            }
            pids += std::to_string(pid);
        }
        std::cout << std::setw(12) << pids << std::setw(12) << socket.inode;
    }

    std::cout << std::endl;
}

void print_live_table(const std::vector<LiveSocket>& sockets, bool detail) {
    int act = 0;

    for (const auto& socket : sockets) {
        if (socket.active) {
            act++;
        }
    }

    std::cout << "---ACTIVE ("<< act << ")---" << std::endl << std::endl;

    std::cout << std::left
    << std::setw(11) << "PROTOCOL |"
    << std::setw(10) << "FAMILY |"
    << std::setw(28) << "LOCAL"
    << std::setw(28) << "REMOTE"
    << std::setw(15) << "STATE"
    << std::setw(13) << "FIRST SEEN"
    << std::setw(12) << "LIFETIME";

    if (detail) {
        std::cout << std::setw(12) << "PIDS" << std::setw(12) << "INODE";
    }

    std::cout << std::endl << std::endl;

    for (const auto& socket : sockets) {
        if (socket.active) {
            print_live_socket_info(socket, detail);
        }
    }

    std::cout << std::endl << std::endl;

    int inact = 0;

    for (const auto& socket : sockets) {
        if (!socket.active) {
            inact++;
        }
    }

    std::cout << "---INACTIVE ("<< inact << ")---" << std::endl << std::endl;

    std::cout << std::left
    << std::setw(11) << "PROTOCOL |"
    << std::setw(10) << "FAMILY |"
    << std::setw(28) << "LOCAL"
    << std::setw(28) << "REMOTE"
    << std::setw(13) << "LAST SEEN"
    << std::setw(12) << "LIFETIME";

    if (detail) {
        std::cout << std::setw(12) << "PIDS" << std::setw(12) << "INODE";
    }

    std::cout << std::endl << std::endl;

    for (const auto& socket : sockets) {
        if (!socket.active) {
            print_live_socket_info(socket, detail);
        }
    }
}