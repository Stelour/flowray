// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.c

#include "ebpf_monitor.h"
#include "ebpf_connect.skel.h"
#include "../headers/proc_name.h"
#include "../headers/pid.h"
#include "../headers/output.h"

#include <iostream>
#include <csignal>
#include <cerrno>
#include <cstdint>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <chrono>
#include <unordered_set>
#include <net/if.h>
#include <unordered_map>
#include <sstream>

struct tcx_links {
    unsigned int ifindex = 0;
    std::string ifname;

    bpf_link* ingress = nullptr;
    bpf_link* egress = nullptr;
};

struct ebpf_monitor {
    ebpf_connect_bpf* skel = nullptr;
    ring_buffer* rb = nullptr;
    std::vector<tcx_links> links;

    std::unordered_set<std::uint32_t> pids;
    std::string proc_name;
    bool pid_tree = false;

    std::vector<event> events;
    std::chrono::steady_clock::time_point last_scan{};
};

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int) {
    exiting = 1;
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

static int handle_event(void *ctx, void *data, size_t data_sz) {
    if (!ctx || !data || data_sz < sizeof(struct event)) {
        return 0;
    }
    auto *m = static_cast<ebpf_monitor*>(ctx);
    const event *e = static_cast<const struct event *>(data);

    // char remote_ip[INET6_ADDRSTRLEN]{};
    //
    // inet_ntop(
    //     e->family,
    //     e->remote_addr,
    //     remote_ip,
    //     sizeof(remote_ip)
    // );
    //
    // std::string res_from_struct;
    //
    // if (e->result == 0) {
    //     res_from_struct = "SUCCESS";
    // }
    // else if (e->result == -EINPROGRESS) {
    //     res_from_struct = "PENDING";
    // }
    // else {
    //     res_from_struct = "FAILED";
    //     return 0;
    // }

    // std::string prt;
    // if (e->protocol == IPPROTO_TCP) {
    //     prt = "TCP";
    // } else if (e->protocol == IPPROTO_UDP) {
    //     prt = "UDP";
    // } else {
    //     prt = "UNKNOWN";
    // }
    //
    // std::string fam;
    // switch (e->family) {
    //     case AF_INET: fam = "IPv4";
    //     case AF_INET6: fam = "IPv6";
    //     default: fam = "UNKNOWN";
    // }

    // std::ostringstream connect_log;
    // connect_log << "PID: " << e->pid << " COMM: " << e->comm << " RESULT: " << res_from_struct << " FAMILY: " << fam
    // << " ADDR: " << remote_ip << ":" << e->remote_port
    // << " PROTOCOL: " << prt << std::endl;

    // m->events.push_back(connect_log.str());

    m->events.push_back(*e);
    return 0;
}

static int update_proc(struct ebpf_connect_bpf* skel, std::unordered_set<std::uint32_t>& tracked_pids,
    bool pid_tree, const std::string& proc_name) {
    if (tracked_pids.empty()) {
        return 1;
    }

    if (!pid_tree && proc_name.empty()) {
        if (!std::filesystem::is_directory("/proc/" + std::to_string(*tracked_pids.begin()))) {
            return 1;
        }
        return 0;
    }

    std::vector<std::uint32_t> cur;
    if (!proc_name.empty()) {
        cur = find_pids_by_name(proc_name);
    } else {
        for (auto pid : tracked_pids) {
            if (std::filesystem::is_directory("/proc/" + std::to_string(pid))) {
                cur.push_back(pid);
            }
        }
    }

    if (pid_tree) {
        for (auto pid : cur) {
            push_pid_tree(pid, cur);
        }
        std::sort(cur.begin(), cur.end());
        cur.erase(
            std::unique(cur.begin(), cur.end()),
            cur.end()
        );
    }

    std::unordered_set current_pids(cur.begin(), cur.end());
    std::uint8_t value = 1;
    int alwfd = bpf_map__fd(skel->maps.allowed_pids);
    for (auto it = tracked_pids.begin(); it != tracked_pids.end();) {
        std::uint32_t pid = *it;
        if (!current_pids.contains(pid)) {
            int err = bpf_map_delete_elem(alwfd, &pid);
            if (err) {
                std::cerr << "Failed delete PID " << pid << std::endl;
                ++it;
            } else {
                it = tracked_pids.erase(it);
            }
        } else {
            ++it;
        }
    }

    for (auto pid : current_pids) {
        if (!tracked_pids.contains(pid)) {
            int err = bpf_map_update_elem(alwfd, &pid, &value, BPF_ANY);
            if (err) {
                std::cerr << "Failed add PID " << pid << std::endl;
            } else {
                tracked_pids.insert(pid);
            }
        }
    }

    return 0;
}

static int seed_ex(struct ebpf_connect_bpf* skel, const std::vector<std::uint32_t>& pids, bool pid_tree) {
    std::vector<ProcessInfo> processes;
    std::vector<SocketInfo> sockets;
    SocketFdMap socket_fds;
    if (get_proc_sockets(pids, pid_tree, processes, sockets, &socket_fds) != status_msg::success) {
        std::cerr << "Failed to scan existing sockets" << std::endl;
        return -1;
    }
    int flow_map_fd = bpf_map__fd(skel->maps.flow_mtr);
    int socket_map_fd = bpf_map__fd(skel->maps.sockets);
    for (const auto& sock : sockets) {
        auto fd_it = socket_fds.find(sock.inode);
        if (fd_it != socket_fds.end()) {
            struct socket_info info{};
            info.family = sock.family;
            info.protocol = sock.protocol;
            if (sock.protocol == IPPROTO_TCP) {
                info.type = SOCK_STREAM;
            }
            else if (sock.protocol == IPPROTO_UDP) {
                info.type = SOCK_DGRAM;
            }
            else {
                continue;
            }
            for (const auto& ref : fd_it->second) {
                std::uint64_t key = (static_cast<std::uint64_t>(ref.pid) << 32) | static_cast<std::uint32_t>(ref.fd);
                if (bpf_map_update_elem(socket_map_fd, &key, &info, BPF_ANY) != 0) {
                    std::cerr << "Failed to seed socket " << "pid=" << ref.pid
                    << " fd=" << ref.fd << ": " << strerror(errno) << std::endl;
                }
            }
        }

        if (sock.family != AF_INET && sock.family != AF_INET6) {
            continue;
        }

        if (sock.remote_port == 0) {
            continue;
        }

        struct flow_key key{};
        key.family = sock.family;
        key.remote_port = sock.remote_port;

        if (inet_pton(sock.family, sock.remote_ip.c_str(), key.remote_addr) != 1) {
            continue;
        }

        struct flow_metrics zero{};

        if (bpf_map_update_elem(flow_map_fd, &key, &zero, BPF_NOEXIST) != 0) {
            if (errno != EEXIST) {
                std::cerr << "Failed to seed flow " << sock.remote_ip << ":" << sock.remote_port << std::endl;
            }
        }
    }

    return 0;
}

static int attach_tcx_interfaces(struct ebpf_connect_bpf* skel, std::vector<tcx_links>& attached) {
    struct if_nameindex* ifs = if_nameindex();

    if (!ifs) {
        std::cerr << "Failed to get network interfaces" << std::endl;
        return 1;
    }

    for (struct if_nameindex* it = ifs; it->if_index != 0 && it->if_name != nullptr; ++it) {
        bpf_tcx_opts opts{};
        opts.sz = sizeof(opts);

        tcx_links links{};
        links.ifindex = it->if_index;
        links.ifname = it->if_name;

        links.ingress = bpf_program__attach_tcx(skel->progs.handle_ingress, it->if_index, &opts);

        if (!links.ingress) {
            std::cerr << "Failed to attach TCX ingress to " << it->if_name << std::endl;
            continue;
        }

        links.egress = bpf_program__attach_tcx(skel->progs.handle_egress, it->if_index, &opts);

        if (!links.egress) {
            std::cerr << "Failed to attach TCX egress to " << it->if_name << std::endl;
            bpf_link__destroy(links.ingress);
            continue;
        }
        attached.push_back(std::move(links));
    }
    if_freenameindex(ifs);
    return attached.empty();
}

static void read_flow_metrics(struct ebpf_connect_bpf* skel, std::vector<ebpf_traffic>& traffic) {
    traffic.clear();
    int map_fd = bpf_map__fd(skel->maps.flow_mtr);

    flow_key current_key{};
    flow_key next_key{};

    const flow_key* current = nullptr;

    while (bpf_map_get_next_key(map_fd, current, &next_key) == 0) {
        flow_metrics metrics{};

        if (bpf_map_lookup_elem(map_fd, &next_key, &metrics) == 0) {
            // char remote_ip[INET6_ADDRSTRLEN]{};
            // const auto* addr = next_key.remote_addr;
            // if (inet_ntop(next_key.family, addr, remote_ip, sizeof(remote_ip))) {
            //     std::cout << "TRAFFIC " << remote_ip << ":" << next_key.remote_port << " | RX: " << metrics.rx_bytes
            //         << " bytes / " << metrics.rx_packets << " packets | TX: " << metrics.tx_bytes
            //         << " bytes / " << metrics.tx_packets << " packets" << std::endl;
            // }
            traffic.push_back({next_key, metrics});
        }
        current_key = next_key;
        current = &current_key;
    }
}

void ebpf_close(ebpf_monitor* m) {
    if (!m) {
        return;
    }

    if (m->rb) {
        ring_buffer__free(m->rb);
    }

    for (auto& link : m->links) {
        if (link.ingress) {
            bpf_link__destroy(link.ingress);
        }
        if (link.egress) {
            bpf_link__destroy(link.egress);
        }
    }

    if (m->skel) {
        ebpf_connect_bpf__destroy(m->skel);
    }

    delete m;
}

ebpf_monitor* ebpf_open(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree) {
    if (pids.empty()) {
        return nullptr;
    }

    auto* m = new ebpf_monitor;
    m->proc_name = proc_name;
    m->pid_tree = pid_tree;

    auto fail = [&]() -> ebpf_monitor* {
        ebpf_close(m);
        return nullptr;
    };

    exiting = 0;
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    auto all_pids = pids;

    if (pid_tree) {
        for (auto pid : pids) {
            push_pid_tree(pid, all_pids);
        }
    }

    std::sort(all_pids.begin(), all_pids.end());
    all_pids.erase(
        std::unique(all_pids.begin(), all_pids.end()),
        all_pids.end()
    );

    m->skel = ebpf_connect_bpf__open();
    if (!m->skel) {
        return fail();
    }

    bpf_program__set_autoattach(m->skel->progs.handle_ingress, false);
    bpf_program__set_autoattach(m->skel->progs.handle_egress, false);

    if (ebpf_connect_bpf__load(m->skel) != 0) {
        return fail();
    }

    std::uint8_t value = 1;
    int fd = bpf_map__fd(m->skel->maps.allowed_pids);

    for (auto pid : all_pids) {
        if (bpf_map_update_elem(fd, &pid, &value, BPF_ANY) != 0) {
            return fail();
        }
        m->pids.insert(pid);
    }

    if (ebpf_connect_bpf__attach(m->skel) != 0) {
        return fail();
    }

    if (seed_ex(m->skel, all_pids, false) != 0) {
        return fail();
    }

    if (attach_tcx_interfaces(m->skel, m->links) != 0) {
        return fail();
    }

    m->rb = ring_buffer__new(bpf_map__fd(m->skel->maps.events), handle_event, m, nullptr);

    if (!m->rb) {
        return fail();
    }

    m->last_scan = std::chrono::steady_clock::now() - std::chrono::seconds(1);

    return m;
}

ebpf_step ebpf_get_step(ebpf_monitor* m, std::vector<event>& events, std::vector<ebpf_traffic>& traffic) {
    events.clear();

    if (!m) {
        return ebpf_step::error;
    }

    if (exiting) {
        return ebpf_step::stopped;
    }

    int err = ring_buffer__poll(m->rb, 10);

    events.swap(m->events);

    if (exiting) {
        return ebpf_step::stopped;
    }

    if (err == -EINTR) {
        return ebpf_step::updated;
    }

    if (err < 0) {
        return ebpf_step::error;
    }

    auto now = std::chrono::steady_clock::now();

    if (now - m->last_scan >= std::chrono::seconds(1)) {
        int result = update_proc(m->skel, m->pids, m->pid_tree, m->proc_name);

        read_flow_metrics(m->skel, traffic);
        m->last_scan = now;

        if (result != 0) {
            return ebpf_step::stopped;
        }
    }

    return ebpf_step::updated;
}

int ebpf_start(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree) {
    auto* m = ebpf_open(pids, proc_name, pid_tree);
    if (!m) {
        std::cerr << "Failed to start eBPF monitor\n";
        return 1;
    }

    std::vector<event> events;
    std::vector<ebpf_traffic> traffic;

    auto last_print = std::chrono::steady_clock::now() - std::chrono::seconds(1);

    int result = 0;

    while (true) {
        auto step = ebpf_get_step(m, events, traffic);

        for (const auto& e : events) {
            char ip[INET6_ADDRSTRLEN]{};

            std::string res_from_struct;

            if (e.result == 0) {
                res_from_struct = "SUCCESS";
            }
            else if (e.result == -EINPROGRESS) {
                res_from_struct = "PENDING";
            }
            else {
                res_from_struct = "FAILED";
                continue;
            }

            if (inet_ntop(e.family, e.remote_addr, ip, sizeof(ip))) {
                std::cout << "PID: " << e.pid << " RESULT: " << res_from_struct << " FAMILY: " << family_to_string(e.family)
                << " PROTOCOL: " << protocol_to_string(e.protocol) << " ADDR: " << ip << ":" << ntohs(e.remote_port) << '\n';
            }
        }

        auto now = std::chrono::steady_clock::now();

        if (now - last_print >= std::chrono::seconds(1)) {
            for (const auto& row : traffic) {
                char ip[INET6_ADDRSTRLEN]{};

                if (inet_ntop(row.key.family, row.key.remote_addr, ip, sizeof(ip))) {
                    std::cout << "TRAFFIC " << ip << ":" << ntohs(row.key.remote_port) << " | RX: " << row.metrics.rx_bytes
                    << " bytes / " << row.metrics.rx_packets << " packets | TX: " << row.metrics.tx_bytes
                    << " bytes / " << row.metrics.tx_packets << " packets" << "\n";
                }
            }

            if (!events.empty()) {
                std::cout << std::flush;
            }
            last_print = now;
        }

        if (step != ebpf_step::updated) {
            result = step == ebpf_step::error ? 1 : 0;
            break;
        }
    }

    ebpf_close(m);
    return result;
}