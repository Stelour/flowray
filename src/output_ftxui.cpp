#include "../headers/output_ftxui.h"
#include "../headers/pid.h"
#include "../ebpf/ebpf_monitor.h"

#include <ftxui/component/app.hpp>             // for Component, App
#include <ftxui/component/component.hpp>       // for Toggle, Renderer, Vertical
#include <ftxui/component/loop.hpp>            // for Loop
#include <ftxui/dom/elements.hpp>              // for text, hbox, vbox, Element
#include <ftxui/component/component_options.hpp>

#include <netinet/in.h>
#include <string>
#include <chrono>
#include <thread>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>
#include <unordered_map>

using namespace ftxui;

static std::string print_process_info(const std::vector<ProcessInfo>& processes) {
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

static std::string socket_row(const LiveSocket& live, bool pid_detail) {
    const auto& s = live.socket;

    std::string state = "-";
    if (live.active) {
        if (s.protocol == IPPROTO_TCP) {
            state = state_to_string(s.state);
        }
    }

    std::ostringstream out;
    out << std::left
    << std::setw(10)  << protocol_to_string(s.protocol)
    << std::setw(10)  << family_to_string(s.family)
    << std::setw(30) << (s.local_ip + ":" + std::to_string(s.local_port))
    << std::setw(30) << (s.remote_ip + ":" + std::to_string(s.remote_port))
    << std::setw(15) << state
    << std::setw(13) << format_time(live.active ? live.first_seen : live.last_seen)
    << std::setw(13) << format_duration(live.last_seen - live.first_seen);

    if (pid_detail) {
        std::string pids;
        for (const auto pid : s.pids) {
            if (!pids.empty()) {
                pids += ',';
            }
            pids += std::to_string(pid);
        }
        out << std::left << std::setw(10) << pids << s.inode;
    }

    return out.str();
}

static Element socket_header(bool active, bool pid_detail) {
    int v_ind = 0;
    int v_pids = 0;
    if (pid_detail) {
        v_ind = 10;
        v_pids = 6;
    }
    return hbox({
        text("  "),
        text("PROTO") | size(WIDTH, EQUAL, 10),
        text("FAMILY") | size(WIDTH, EQUAL, 10),
        text("LOCAL") | size(WIDTH, EQUAL, 30),
        text("REMOTE") | size(WIDTH, EQUAL, 30),
        text("STATE") | size(WIDTH, EQUAL, 15),
        text(active ? "FIRST SEEN" : "LAST SEEN") | size(WIDTH, EQUAL, 13),
        text("LIFETIME") | size(WIDTH, EQUAL, 13),
        text("INODE") | size(WIDTH, EQUAL, v_ind),
        text("PIDs") | size(WIDTH, EQUAL, v_pids),
    });
}

status_msg output_table_socket_live(std::vector<std::uint32_t> pids,
    bool pid_tree, bool pid_detail, const std::string& proc_name) {
    std::string nm = proc_name;
    if (proc_name.empty()) {
        for (auto pid : pids) {
            nm = std::to_string(pid);
        }
    }

    std::vector<LiveSocket> live_sockets;
    std::vector<ProcessInfo> processes;
    update_live_data(pids, pid_tree, proc_name, processes, live_sockets);

    auto app = App::Fullscreen();

    std::vector<std::string> active_rows;
    std::vector<std::string> inactive_rows;
    int active_selected = 0;
    int inactive_selected = 0;

    auto refresh_rows = [&] {
        active_rows.clear();
        inactive_rows.clear();

        for (const auto& socket : live_sockets) {
            auto& rows = socket.active ? active_rows : inactive_rows;
            rows.push_back(socket_row(socket, pid_detail));
        }

        auto clamp = [](int& selected, std::size_t count) {
            selected = std::clamp(selected, 0, count ? int(count) - 1 : 0);
        };

        clamp(active_selected, active_rows.size());
        clamp(inactive_selected, inactive_rows.size());
    };

    refresh_rows();

    auto active_menu = Menu(&active_rows, &active_selected);
    auto inactive_menu = Menu(&inactive_rows, &inactive_selected);

    auto menus = Container::Vertical({active_menu, inactive_menu});

    auto component = Renderer(menus, [&] {
        return vbox({
            text("FLOWRAY - LIVE SOCKETS") | color(Color::Pink3) | hcenter,
            text(""),
            text("PIDs (" + nm + ") : " + std::to_string(processes.size())),
            paragraph(" - " + print_process_info(processes)),
            text(""),
            text("Sockets: " + std::to_string(live_sockets.size())),
            text("Active Sockets: " + std::to_string(active_rows.size())),
            separator(),
            text("ACTIVE (" + std::to_string(active_rows.size()) + ")") | hcenter,
            socket_header(true, pid_detail),
            text(""),
            active_menu->Render() | vscroll_indicator | frame | flex,
            text(""),
            separator(),
            text("INACTIVE (" + std::to_string(inactive_rows.size()) + ")") | hcenter,
            socket_header(false, pid_detail),
            text(""),
            inactive_menu->Render() | vscroll_indicator | frame | flex,
            text(""),
            text("↑/↓ - select | Tab - switch list | q/Esc - exit") | dim,
        });
    });

    bool act_foc = true;
    active_menu->TakeFocus();
    component |= CatchEvent([&](const Event& event) -> bool {
        if (event == Event::Character('q') || event == Event::Escape) {
            app.Exit();
            return true;
        }

        if (event == Event::Tab || event == Event::TabReverse) {
            act_foc = !act_foc;
            if (act_foc) {
                active_menu->TakeFocus();
            } else {
                inactive_menu->TakeFocus();
            }
        }
        return false;
    });

    Loop loop(&app, component);

    auto lt = std::chrono::system_clock::now();
    while (!loop.HasQuitted()) {
        if (lt + std::chrono::milliseconds(100) <= std::chrono::system_clock::now()) {
            update_live_data(pids, pid_tree, proc_name, processes, live_sockets);
            refresh_rows();
            app.RequestAnimationFrame();
            lt = std::chrono::system_clock::now();
        }
        loop.RunOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    return status_msg::success;
}

static std::string ebpf_event_row(const event& e) {
    char ip[INET6_ADDRSTRLEN]{};
    inet_ntop(e.family, e.remote_addr, ip, sizeof(ip));

    std::string result;
    if (e.result == 0) {
        result = "SUCCESS";
    } else if (e.result == -EINPROGRESS) {
        result = "PENDING";
    } else {
        result = "FAILED";
    }

    std::string remote = e.family == AF_INET6 ? "[" + std::string(ip) + "]" : std::string(ip);
    // remote += ":" + std::to_string(e.remote_port);

    std::ostringstream out;
    out << std::left << std::setw(10) << e.pid << std::setw(12) << result
    << std::setw(10) << family_to_string(e.family) << std::setw(10) << protocol_to_string(e.protocol) << remote;

    return out.str();
}

static Element ebpf_event_header() {
    return hbox({
        text("  "),
        text("PID") | size(WIDTH, EQUAL, 10),
        text("RESULT") | size(WIDTH, EQUAL, 12),
        text("FAMILY") | size(WIDTH, EQUAL, 10),
        text("PROTO") | size(WIDTH, EQUAL, 10),
        text("REMOTE IP"),
    });
}

static std::string ebpf_traffic_row(const ebpf_traffic& traffic, double rx_speed,
    double tx_speed, double rx_packets, double tx_packets, bool pid_detail) {
    const auto& m = traffic.metrics;
    const auto& key = traffic.key;

    char ip[INET6_ADDRSTRLEN]{};
    inet_ntop(key.family, key.remote_addr, ip, sizeof(ip));

    std::string remote = ip;
    if (pid_detail) {
        if (key.family == AF_INET6) {
            remote = "[" + remote + "]";
        }
        remote += ":" + std::to_string(key.remote_port);
    }

    std::ostringstream out;
    out << std::left << std::fixed << std::setprecision(1);
    if (pid_detail) {
        out << std::setw(10) << protocol_to_string(key.protocol)
        << std::setw(10) << family_to_string(key.family);
    }
    out << std::setw(40) << remote
    << std::setw(30)
    << (std::to_string(m.rx_bytes / 1024) + " KiB (" + std::to_string(static_cast<unsigned long long>(rx_speed / 1024)) + " KiB/s)")
    << std::setw(30)
    << (std::to_string(m.tx_bytes / 1024) + " KiB (" + std::to_string(static_cast<unsigned long long>(tx_speed / 1024)) + " KiB/s)")
    << std::setw(25)
    << (std::to_string(m.rx_packets) + " (" + std::to_string(static_cast<unsigned long long>(rx_packets)) + " pkt/s)")
    << std::setw(25)
    << (std::to_string(m.tx_packets) + " (" + std::to_string(static_cast<unsigned long long>(tx_packets)) + " pkt/s)");

    return out.str();
}

static Element ebpf_traffic_header(bool pid_detail) {
    Elements columns = {text("  ")};
    if (pid_detail) {
        columns.push_back(text("PROTO") | size(WIDTH, EQUAL, 10));
        columns.push_back(text("FAMILY") | size(WIDTH, EQUAL, 10));
    }
    columns.push_back(text(pid_detail ? "REMOTE IP:PORT" : "REMOTE IP") | size(WIDTH, EQUAL, 40));
    columns.push_back(text("RX KiB ↓") | size(WIDTH, EQUAL, 30));
    columns.push_back(text("TX KiB ↑") | size(WIDTH, EQUAL, 30));
    columns.push_back(text("RX pkt ↓") | size(WIDTH, EQUAL, 25));
    columns.push_back(text("TX pkt ↑") | size(WIDTH, EQUAL, 25));
    return hbox(columns);
}

static void update_ebpf_rows(const std::vector<ebpf_traffic>& traffic,
    std::unordered_map<std::string, flow_metrics>& previous,
    std::chrono::steady_clock::time_point& last_sample,
    bool pid_detail, std::vector<std::string>& traffic_rows) {

    auto now = std::chrono::steady_clock::now();
    double seconds = std::chrono::duration<double>(now - last_sample).count();
    std::unordered_map<std::string, ebpf_traffic> grouped;

    for (const auto& row : traffic) {
        char ip[INET6_ADDRSTRLEN]{};
        if (!inet_ntop(row.key.family, row.key.remote_addr, ip, sizeof(ip))) {
            continue;
        }
        std::string key = ip;
        if (pid_detail) {
            key += "/" + std::to_string(row.key.protocol) + "/" + std::to_string(row.key.remote_port);
        }
        auto& sum = grouped[key];
        sum.key = row.key;
        sum.metrics.rx_bytes += row.metrics.rx_bytes;
        sum.metrics.tx_bytes += row.metrics.tx_bytes;
        sum.metrics.rx_packets += row.metrics.rx_packets;
        sum.metrics.tx_packets += row.metrics.tx_packets;
    }

    std::vector<std::pair<std::uint64_t, std::string>> rows;
    for (const auto& [key, row] : grouped) {
        const auto& m = row.metrics;
        auto& old = previous.try_emplace(key, m).first->second;
        auto rate = [&](auto value, auto before) {
            return seconds > 0 && value >= before
                ? double(value - before) / seconds : 0.0;
        };
        double rx = rate(m.rx_bytes, old.rx_bytes);
        double tx = rate(m.tx_bytes, old.tx_bytes);
        rows.emplace_back(rx + tx, ebpf_traffic_row(row, rx, tx,
            rate(m.rx_packets, old.rx_packets),
            rate(m.tx_packets, old.tx_packets), pid_detail));
        old = m;
    }

    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        return a.first != b.first ? a.first > b.first : a.second < b.second;
    });

    traffic_rows.clear();
    for (const auto& row : rows) {
        traffic_rows.push_back(row.second);
    }

    last_sample = now;
}

status_msg output_ebpf_live(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree, bool pid_detail) {
    std::string nm = proc_name;
    if (proc_name.empty()) {
        for (auto pid : pids) {
            nm += std::to_string(pid);
        }
    }

    auto *monitor = ebpf_open(pids, proc_name, pid_tree);
    if (!monitor) {
        return status_msg::error;
    }

    std::vector<ProcessInfo> processes;
    std::vector<SocketInfo> sockets;

    if (get_proc_sockets(pids, pid_tree, processes, sockets, nullptr) != status_msg::success) {
        ebpf_close(monitor);
        return status_msg::error;
    }

    std::vector<event> events;
    std::vector<ebpf_traffic> traffic;
    std::vector<std::string> traffic_rows;
    std::vector<std::string> event_rows;
    int selected_traffic = 0;
    int selected_event = 0;

    auto app = App::Fullscreen();
    auto traffic_menu = Menu(&traffic_rows, &selected_traffic);
    auto event_menu = Menu(&event_rows, &selected_event);
    auto menus = Container::Vertical({traffic_menu, event_menu});

    auto component = Renderer(menus, [&] {
        return vbox({
            text("FLOWRAY - TRAFFIC ANALYZER") | color(Color::Pink3) | hcenter,
            text(""),
            text("PIDs (" + nm + ") : " + std::to_string(processes.size())),
            paragraph(" - " + print_process_info(processes)),
            text(""),
            separator(),
            text("TRAFFIC (" + std::to_string(traffic_rows.size()) + ")") | hcenter,
            text(""),
            ebpf_traffic_header(pid_detail),
            text(""),
            traffic_menu->Render() | vscroll_indicator | frame | flex,
            separator(),
            text("CONNECTION LOGS (" + std::to_string(event_rows.size()) + ")") | hcenter,
            ebpf_event_header(),
            event_menu->Render() | vscroll_indicator | frame | size(HEIGHT, EQUAL, 10),
            text(""),
            text("↑/↓ - select | Tab - switch list | q/Esc - exit") | dim,
        });
    });

    bool act_foc = true;
    traffic_menu->TakeFocus();
    component |= CatchEvent([&](const Event& event) -> bool {
        if (event == Event::Character('q') || event == Event::Escape) {
            app.Exit();
            return true;
        }

        if (event == Event::Tab || event == Event::TabReverse) {
            act_foc = !act_foc;
            if (act_foc) {
                traffic_menu->TakeFocus();
            } else {
                event_menu->TakeFocus();
            }
            return true;
        }
        return false;
    });

    std::unordered_map<std::string, flow_metrics> previous;
    auto last_sample = std::chrono::steady_clock::now();
    status_msg result = status_msg::success;

    Loop loop(&app, component);
    while (!loop.HasQuitted()) {
        bool traffic_updated = false;
        auto step = ebpf_get_step(monitor, events, traffic, &traffic_updated);

        for (const auto& e : events) {
            event_rows.push_back(ebpf_event_row(e));
        }

        if (traffic_updated) {
            update_ebpf_rows(traffic, previous, last_sample, pid_detail, traffic_rows);
            selected_traffic = std::clamp(selected_traffic, 0, traffic_rows.empty() ? 0 : int(traffic_rows.size()) - 1);
        }

        if (!events.empty() || traffic_updated) {
            app.RequestAnimationFrame();
        }

        if (step != ebpf_step::updated) {
            result = step == ebpf_step::error ? status_msg::error : status_msg::success;
            break;
        }

        loop.RunOnce();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ebpf_close(monitor);
    return result;
}