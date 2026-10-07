// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.c

#include "ebpf_monitor.h"
#include "ebpf_connect.skel.h"
#include "../headers/proc_name.h"
#include "../headers/pid.h"
#include "../headers/export.h"
#include "../headers/data.h"
#include "../headers/supp_funcs.h"

#include <iostream>
#include <csignal>
#include <cerrno>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <chrono>
#include <unordered_set>
#include <net/if.h>
#include <unordered_map>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>

// struct tcx_links {
//     unsigned int ifindex = 0;
//     std::string ifname;
//
//     bpf_link* ingress = nullptr;
//     bpf_link* egress = nullptr;
// };

struct ebpf_monitor {
    ebpf_connect_bpf* skel = nullptr;
    ring_buffer* rb = nullptr;
    std::vector<bpf_link*> links;

    std::unordered_set<std::uint32_t> pids;
    std::string proc_name;
    bool pid_tree = false;

    std::vector<event> events;
    std::vector<dns_query> dns_queries;
    std::chrono::steady_clock::time_point last_scan{};
};

static volatile sig_atomic_t exiting = 0;

static void handle_signal(int) {
    exiting = 1;
}

static bool read_dns_name(const unsigned char* data, std::size_t size, std::size_t& offset, std::string& name) {
    std::size_t pos = offset;
    std::size_t wire_len = 1;
    bool jumped = false;
    name.clear();

    for (unsigned steps = 0; steps < 512; ++steps) {
        if (pos >= size) {
            return false;
        }

        unsigned len = data[pos++];

        if ((len & 0xc0) == 0xc0) {
            if (pos >= size) {
                return false;
            }

            std::size_t target = ((len & 0x3f) << 8) | data[pos++];

            if (target >= pos - 2){
                return false;
            }

            if (!jumped) {
                offset = pos;
            }

            jumped = true;
            pos = target;
            continue;
        }

        if (len & 0xc0) {
            return false;
        }

        if (len == 0) {
            if (!jumped) {
                offset = pos;
            }

            if (name.empty()) {
                name = ".";
            }

            return true;
        }

        wire_len += len + 1;
        if (wire_len > 255 || len > size - pos) {
            return false;
        }

        if (!name.empty()) {
            name += '.';
        }

        for (unsigned i = 0; i < len; ++i) {
            unsigned c = data[pos++];
            if (c > 32 && c < 127 && c != '.' && c != '\\') {
                name += static_cast<char>(c);
            } else {
                name += '\\';
                name += static_cast<char>('0' + c / 100);
                name += static_cast<char>('0' + (c / 10) % 10);
                name += static_cast<char>('0' + c % 10);
            }
        }
    }
    return false;
}

static int handle_dns_event(void* ctx, void* data, size_t data_sz) {
    if (!ctx || !data || data_sz < sizeof(dns_event)) {
        return 0;
    }

    auto* m = static_cast<ebpf_monitor*>(ctx);
    const auto* e = static_cast<const dns_event*>(data);

    std::size_t size = e->captured_len;
    if (size < 12 || size > FLOWRAY_DNS_CAPTURE_LEN) {
        return 0;
    }

    const auto* bytes = e->data;

    if (bytes[2] & 0xf8) {
        return 0;
    }

    unsigned questions = (static_cast<unsigned>(bytes[4]) << 8) | bytes[5];

    if (!questions || questions > (size - 12) / 5) {
        return 0;
    }

    std::size_t offset = 12;
    std::vector<dns_query> parsed;

    for (unsigned i = 0; i < questions; ++i) {
        dns_query query{};
        query.pid = e->pid;

        if (!read_dns_name(bytes, size, offset, query.domain)) {
            return 0;
        }

        if (offset > size || size - offset < 4) {
            return 0;
        }

        query.type = (static_cast<unsigned>(bytes[offset]) << 8) | bytes[offset + 1];

        offset += 4;
        parsed.push_back(std::move(query));
    }

    for (auto& query : parsed) {
        m->dns_queries.push_back(std::move(query));
    }

    return 0;
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

static int seed_ex(ebpf_connect_bpf* skel, const std::vector<std::uint32_t>& pids, bool pid_tree) {
    std::vector<ProcessInfo> processes;
    std::vector<SocketInfo> sockets;
    SocketFdMap socket_fds;

    if (get_proc_sockets(pids, pid_tree, processes, sockets, &socket_fds) != status_msg::success) {
        std::cerr << "Failed to scan existing sockets" << std::endl;;
        return -1;
    }

    int owners_fd = bpf_map__fd(skel->maps.socket_owners);
    int sockets_fd = bpf_map__fd(skel->maps.sockets);

    for (const auto& sock : sockets) {
        if ((sock.family != AF_INET && sock.family != AF_INET6) || (sock.protocol != IPPROTO_TCP && sock.protocol != IPPROTO_UDP)) {
            continue;
        }

        auto it = socket_fds.find(sock.inode);
        if (it == socket_fds.end()) {
            continue;
        }

        socket_info info{};
        info.family = sock.family;
        info.protocol = sock.protocol;
        info.type = sock.protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM;

        for (const auto& ref : it->second) {
            int pidfd = syscall(SYS_pidfd_open, ref.pid, 0);
            if (pidfd < 0) {
                if (errno == ESRCH) {
                    continue;
                }

                std::cerr << "pidfd_open: " << strerror(errno) << std::endl;
                return -1;
            }

            int fd = syscall(SYS_pidfd_getfd, pidfd, ref.fd, 0);
            int error = fd < 0 ? errno : 0;
            close(pidfd);
            if (fd < 0) {
                if (error == EBADF || error == ESRCH) {
                    continue;
                }
                std::cerr << "pidfd_getfd: " << strerror(error) << std::endl;
                return -1;
            }

            struct stat st{};
            std::uint64_t cookie{};
            socklen_t size = sizeof(cookie);

            int result = fstat(fd, &st);
            if (result == 0) {
                result = getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &size);
            }
            error = result < 0 ? errno : 0;
            close(fd);

            if (result < 0) {
                if (error == ENOTSOCK) {
                    continue;
                }

                std::cerr << "Failed to inspect socket: " << strerror(error) << std::endl;
                return -1;
            }

            if (!S_ISSOCK(st.st_mode) || st.st_ino != sock.inode) {
                continue;
            }

            if (size != sizeof(cookie) || cookie == 0) {
                std::cerr << "Invalid socket cookie" << std::endl;
                return -1;
            }

            std::uint32_t pid = ref.pid;
            if (bpf_map_update_elem(owners_fd, &cookie, &pid, BPF_NOEXIST) != 0 && errno != EEXIST) {
                std::cerr << "Failed to seed owner: " << strerror(errno) << std::endl;
                return -1;
            }

            std::uint64_t key = (static_cast<std::uint64_t>(pid) << 32) | static_cast<std::uint32_t>(ref.fd);
            if (bpf_map_update_elem(sockets_fd, &key, &info, BPF_ANY) != 0) {
                std::cerr << "Failed to seed socket: " << strerror(errno) << std::endl;
                return -1;
            }
        }
    }

    return 0;
}

static int update_proc(struct ebpf_connect_bpf* skel, std::unordered_set<std::uint32_t>& tracked_pids,
    bool pid_tree, const std::string& proc_name) {
    std::vector<std::uint32_t> added_pids;
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
        const auto roots = cur;
        for (auto pid : roots) {
            push_pid_tree(pid, cur);
        }
        std::sort(cur.begin(), cur.end());
        cur.erase(std::unique(cur.begin(), cur.end()), cur.end());
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
                added_pids.push_back(pid);
            }
        }
    }

    if (!added_pids.empty() && seed_ex(skel, added_pids, false) != 0) {
        return -1;
    }
    return 0;
}

// static int attach_tcx_interfaces(struct ebpf_connect_bpf* skel, std::vector<tcx_links>& attached) {
//     struct if_nameindex* ifs = if_nameindex();
//
//     if (!ifs) {
//         std::cerr << "Failed to get network interfaces" << std::endl;
//         return 1;
//     }
//
//     for (struct if_nameindex* it = ifs; it->if_index != 0 && it->if_name != nullptr; ++it) {
//         bpf_tcx_opts opts{};
//         opts.sz = sizeof(opts);
//
//         tcx_links links{};
//         links.ifindex = it->if_index;
//         links.ifname = it->if_name;
//
//         links.ingress = bpf_program__attach_tcx(skel->progs.handle_ingress, it->if_index, &opts);
//
//         if (!links.ingress) {
//             std::cerr << "Failed to attach TCX ingress to " << it->if_name << std::endl;
//             continue;
//         }
//
//         links.egress = bpf_program__attach_tcx(skel->progs.handle_egress, it->if_index, &opts);
//
//         if (!links.egress) {
//             std::cerr << "Failed to attach TCX egress to " << it->if_name << std::endl;
//             bpf_link__destroy(links.ingress);
//             continue;
//         }
//         attached.push_back(std::move(links));
//     }
//     if_freenameindex(ifs);
//     return attached.empty();
// }

static int attach_cgroup(ebpf_connect_bpf* skel, std::vector<bpf_link*>& attached) {
    int cgfd = open(
        "/sys/fs/cgroup",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC
    );

    if (cgfd < 0) {
        std::cerr << "Failed to open cgroup: " << strerror(errno) << '\n';
        return -1;
    }

    struct target {
        bpf_program* prog;
        const char* name;
    };

    const target targets[] = {
        {skel->progs.handle_sock_create,  "sock_create"},
        {skel->progs.handle_sock_release, "sock_release"},
        {skel->progs.handle_ingress,      "ingress"},
        {skel->progs.handle_egress,       "egress"},
    };

    for (const auto& target : targets) {
        bpf_link* link = bpf_program__attach_cgroup(target.prog, cgfd);

        long err = libbpf_get_error(link);

        if (!link || err) {
            int error = err ? static_cast<int>(-err) : errno;
            std::cerr << "Failed to attach cgroup " << target.name << ": " << strerror(error) << '\n';
            close(cgfd);
            return -1;
        }

        attached.push_back(link);
    }

    close(cgfd);
    return 0;
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

    for (bpf_link* link : m->links) {
        bpf_link__destroy(link);
    }

    if (m->skel) {
        ebpf_connect_bpf__destroy(m->skel);
    }

    delete m;
}

ebpf_monitor* ebpf_open(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree, std::uint64_t ring_buf_size) {
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

    int err = bpf_map__set_max_entries(m->skel->maps.events, ring_buf_size);

    if (err) {
        std::cerr << "Failed to set ring buffer size: " << ring_buf_size << '\n';
        return fail();
    }

    bpf_program__set_autoattach(m->skel->progs.handle_sock_create, false);
    bpf_program__set_autoattach(m->skel->progs.handle_sock_release, false);
    bpf_program__set_autoattach(m->skel->progs.handle_ingress, false);
    bpf_program__set_autoattach(m->skel->progs.handle_egress, false);

    int load_err = ebpf_connect_bpf__load(m->skel);
    if (load_err != 0) {
        std::cerr << "BPF load failed: " << load_err << '\n';
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

    int attach_err = ebpf_connect_bpf__attach(m->skel);
    if (attach_err != 0) {
        std::cerr << "BPF autoattach failed: " << attach_err << '\n';
        return fail();
    }

    if (attach_cgroup(m->skel, m->links) != 0) {
        std::cerr << "Cgroup attach failed\n";
        return fail();
    }

    if (seed_ex(m->skel, all_pids, false) != 0) {
        std::cerr << "Socket seed failed\n";
        return fail();
    }

    m->rb = ring_buffer__new(bpf_map__fd(m->skel->maps.events), handle_event, m, nullptr);

    if (!m->rb) {
        return fail();
    }

    int dns_err = ring_buffer__add(m->rb, bpf_map__fd(m->skel->maps.dns_events), handle_dns_event, m);

    if (dns_err != 0) {
        std::cerr << "Failed to add DNS ring buffer: " << dns_err << '\n';
        return fail();
    }

    m->last_scan = std::chrono::steady_clock::now() - std::chrono::seconds(1);

    return m;
}

ebpf_step ebpf_get_step(ebpf_monitor* m, std::vector<event>& events, std::vector<ebpf_traffic>& traffic,
    bool* traffic_updated, std::vector<dns_query>* dns) {
    events.clear();

    if (dns) {
        dns->clear();
    }

    if (traffic_updated) {
        *traffic_updated = false;
    }

    if (!m) {
        return ebpf_step::error;
    }

    if (exiting) {
        return ebpf_step::stopped;
    }

    int err = ring_buffer__poll(m->rb, 10);

    events.swap(m->events);

    if (dns) {
        dns->swap(m->dns_queries);
    } else {
        m->dns_queries.clear();
    }

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

        if (traffic_updated) {
            *traffic_updated = true;
        }

        m->last_scan = now;

        if (result < 0) {
            return ebpf_step::error;
        }

        if (result > 0) {
            return ebpf_step::stopped;
        }
    }

    return ebpf_step::updated;
}

int ebpf_start(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree,
    std::uint64_t ring_buf_size, const std::string& path) {

    bool exp = false;
    if (!path.empty()) {
        exp = true;
    }

    auto* m = ebpf_open(pids, proc_name, pid_tree, ring_buf_size);
    if (!m) {
        std::cerr << "Failed to start eBPF monitor\n";
        return 1;
    }

    std::vector<event> events;
    std::vector<ebpf_traffic> traffic;
    std::vector<event> events_history;

    auto last_print = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    auto lt2 = std::chrono::system_clock::now();

    int result = 0;

    std::vector<dns_query> dns;

    while (true) {
        auto step = ebpf_get_step(m, events, traffic, nullptr, &dns);

        for (const auto& query : dns) {
            std::cout << "DNS | PID " << query.pid << " | " << query.domain << " | " << dns_type_to_string(query.type) << '\n';
        }

        if (!dns.empty()) {
            std::cout << std::flush;
        }

        events_history.insert(events_history.end(), events.begin(), events.end());

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
                << " PROTOCOL: " << protocol_to_string(e.protocol) << " ADDR: " << ip << ":" << e.remote_port << '\n';
            }
        }

        auto now = std::chrono::steady_clock::now();

        if (now - last_print >= std::chrono::seconds(1)) {
            for (const auto& row : traffic) {
                char ip[INET6_ADDRSTRLEN]{};

                if (inet_ntop(row.key.family, row.key.remote_addr, ip, sizeof(ip))) {
                    std::cout << "TRAFFIC " << ip << ":" << row.key.remote_port << " | RX: " << row.metrics.rx_bytes
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

        if ((exp) && (lt2 + std::chrono::milliseconds(1000) <= std::chrono::system_clock::now())) {
            if (export_ebpf_json(path, pids, proc_name, traffic, events_history) != status_msg::success) {
                std::cerr << "Failed write to file" << path << std::endl;
                continue;
            }
            lt2 = std::chrono::system_clock::now();
        }
    }

    ebpf_close(m);
    return result;
}