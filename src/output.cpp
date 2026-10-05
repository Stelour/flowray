#include "../headers/output.h"

#include <iostream>
#include <netinet/in.h>
#include <string>
#include <iomanip>
#include <chrono>

static std::string state_to_string(std::uint8_t state) {
    switch (state) {
        case 1: return "ESTABLISHED";
        case 2: return "SYN_SENT";
        case 3: return "SYN_RECV";
        case 4: return "FIN_WAIT1";
        case 5: return "FIN_WAIT2";
        case 6: return "TIME_WAIT";
        case 7: return "CLOSE";
        case 8: return "CLOSE_WAIT";
        case 9: return "LAST_ACK";
        case 10: return "LISTEN";
        case 11: return "CLOSING";
        case 12: return "NEW_SYN_RECV";
        default: return "UNKNOWN";
    }
}

static std::string protocol_to_string(int protocol) {
    switch (protocol) {
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        default: return "UNKNOWN";
    }
}

static std::string family_to_string(int family) {
    switch (family) {
        case AF_INET: return "IPv4";
        case AF_INET6: return "IPv6";
        default: return "UNKNOWN";
    }
}

void print_process_info(std::span<ProcessInfo> processes) {
    std::cout << "Processes (" << processes.size() << ")" << std::endl;
    for (const auto& process : processes) {
        std::cout << "\t" << process.name << "[" << process.pid <<  "]" << std::endl;
    }
    std::cout << std::endl;
}

void print_socket_info(std::span<SocketInfo> sockets, bool detail) {
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

void print_live_table(std::span<LiveSocket> sockets, bool detail) {
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