#include "../headers/output_ftxui.h"
#include "../headers/pid.h"

#include <ftxui/component/app.hpp>             // for Component, App
#include <ftxui/component/component.hpp>       // for Toggle, Renderer, Vertical
#include <ftxui/component/loop.hpp>            // for Loop
#include <ftxui/dom/elements.hpp>              // for text, hbox, vbox, Element

#include <netinet/in.h>
#include <string>
#include <chrono>
#include <thread>
#include <span>

using namespace ftxui;

static std::string print_process_info(const std::span<ProcessInfo> processes) {
    std::string procs;
    for (const auto& process : processes) {
        procs += process.name + "[" + std::to_string(process.pid) + "]  ";
    }
    return procs;
}

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

static Element output_sock_el(const LiveSocket& live_socket) {
    const auto& socket = live_socket.socket;
    int value = 0;
    std::string state = "-";
    if (live_socket.active) {
        value += 15;
        if (socket.protocol == IPPROTO_TCP) {
            state = state_to_string(socket.state);
        }
    }
    return hbox({
        text(protocol_to_string(socket.protocol)) | size(WIDTH, EQUAL, 10),
        text(family_to_string(socket.family))  | size(WIDTH, EQUAL, 10),
        text(socket.local_ip + ":" + std::to_string(socket.local_port))  | size(WIDTH, EQUAL, 30),
        text(socket.remote_ip + ":" + std::to_string(socket.remote_port))  | size(WIDTH, EQUAL, 30),
        text(live_socket.active ? state : "") | size(WIDTH, EQUAL, value),
        text(live_socket.active ? format_time(live_socket.first_seen) : format_time(live_socket.last_seen)) | size(WIDTH, EQUAL, 13),
        text(format_duration(live_socket.last_seen - live_socket.first_seen)) | size(WIDTH, EQUAL, 13)
    });
}

status_msg output_table_socket_live(std::vector<std::uint32_t> pids,
    bool pid_tree, bool pid_detail, const std::string& proc_name) {
    std::vector<LiveSocket> live_sockets;
    std::vector<ProcessInfo> processes;
    update_live_data(pids, pid_tree, proc_name, processes, live_sockets);

    auto app = App::Fullscreen();

    auto component = Renderer([&]{
        int active_c = 0;
        int inactive_c = 0;
        for (const auto& socket : live_sockets) {
            if (socket.active) {
                active_c++;
            } else {
                inactive_c++;
            }
        }
        Elements sock_r_active;
        Elements sock_r_inactive;
        for (const auto& live_socket : live_sockets) {
            if (live_socket.active) {
                sock_r_active.push_back(output_sock_el(live_socket));
            }
        }

        for (const auto& live_socket : live_sockets) {
            if (!live_socket.active) {
                sock_r_inactive.push_back(output_sock_el(live_socket));
            }
        }

        return vbox({
            text("FLOWRAY - LIVE SOCKETS") | color(Color::Purple) | hcenter,
            separator(),
            text("PIDs: " + std::to_string(processes.size())),
            paragraph(" - " + print_process_info(processes)),
            text(""),
            text("Sockets: " + std::to_string(live_sockets.size())),
            text("Active Sockets: " + std::to_string(active_c)),
            separator(),
            text("ACTIVE (" + std::to_string(active_c) + ")") | hcenter,
            text(""),
            hbox ({
                text("PROTO") | size(WIDTH, EQUAL, 10),
                text("FAMILY") | size(WIDTH, EQUAL, 10),
                text("LOCAL") | size(WIDTH, EQUAL, 30),
                text("REMOTE") | size(WIDTH, EQUAL, 30),
                text("STATE") | size(WIDTH, EQUAL, 15),
                text("FIRST SEEN") | size(WIDTH, EQUAL, 13),
                text("LIFETIME") | size(WIDTH, EQUAL, 13),
            }),
            vbox(std::move(sock_r_active)) | flex,
            separator(),
            text("INACTIVE (" + std::to_string(inactive_c) + ")") | hcenter,
            text(""),
            hbox ({
                text("PROTO") | size(WIDTH, EQUAL, 10),
                text("FAMILY") | size(WIDTH, EQUAL, 10),
                text("LOCAL") | size(WIDTH, EQUAL, 30),
                text("REMOTE") | size(WIDTH, EQUAL, 30),
                text("FIRST SEEN") | size(WIDTH, EQUAL, 13),
                text("LIFETIME") | size(WIDTH, EQUAL, 13),
            }),
            vbox(std::move(sock_r_inactive)) | flex,
            text("q - exit") | dim,
        }) | border;
    });

    component |= CatchEvent([&](const Event& event) -> bool {
        if (event == Event::Character('q') || event == Event::Escape) {
            app.Exit();
            return true;
        }
        return false;
    });

    Loop loop(&app, component);

    auto lt = std::chrono::system_clock::now();
    while (!loop.HasQuitted()) {
        if (lt + std::chrono::milliseconds(100) <= std::chrono::system_clock::now()) {
            update_live_data(pids, pid_tree, proc_name, processes, live_sockets);
            app.RequestAnimationFrame();
            lt = std::chrono::system_clock::now();
        }
        loop.RunOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return status_msg::success;
}
