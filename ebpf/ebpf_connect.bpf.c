// https://github.com/libbpf/libbpf-bootstrap/tree/master/examples/c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/minimal.bpf.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/bootstrap.bpf.c
// https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/kprobe.bpf.c

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"

// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "ebpf.h"

#define ETH_P_IP   0x0800 /*Internet Protocol packet*/
#define ETH_P_IPV6 0x86DD

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct event);
} pending_connects SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 16384);
//     __type(key, __u64);
//     __type(value, struct event);
// } pending_sendto SEC(".maps");
//
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 4096);
//     __type(key, __u64);
//     __type(value, struct event);
// } pending_sendmsg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct socket_info);
} tmp_sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct socket_info);
} sockets SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} allowed_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_mtr SEC(".maps");

static int parse_user_sockaddr(void *addr, struct event *e) {
    if (!addr) {
        return -1;
    }

    __u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), addr) < 0) {
        return -1;
    }

    if (family != AF_INET && family != AF_INET6) {
        return -1;
    }

    e->family = family;

    if (family == AF_INET) {
        struct sockaddr_in addr4 = {};
        if (bpf_probe_read_user(&addr4, sizeof(addr4), addr) < 0) {
            return -1;
        }
        __builtin_memcpy(e->remote_addr, &addr4.sin_addr, sizeof(addr4.sin_addr));
        e->remote_port = bpf_ntohs(addr4.sin_port);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr6 = {};
        if (bpf_probe_read_user(&addr6, sizeof(addr6), addr) < 0) {
            return -1;
        }
        __builtin_memcpy(e->remote_addr, &addr6.sin6_addr, sizeof(addr6.sin6_addr));
        e->remote_port = bpf_ntohs(addr6.sin6_port);
    } else {
        return -1;
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 tid = (__u32)id;

    if (!bpf_map_lookup_elem(&allowed_pids, &pid)) {
        return 0;
    }

    int fd = (int)ctx->args[0];
    void *addr = (void *)ctx->args[1];
    // int addrlen = (int)ctx->args[2];

    if (!addr) {
        return 0;
    }

    struct event e = {};

    if (parse_user_sockaddr(addr, &e) < 0) {
        return 0;
    }

    e.pid = pid;
    e.tid = tid;
    e.fd = fd;

    bpf_get_current_comm(e.comm, sizeof(e.comm));

    __u64 key = ((__u64)pid << 32) | (__u32)fd;
    struct socket_info *info = bpf_map_lookup_elem(&sockets, &key);
    if (info) {
        e.type = info->type;
        e.protocol = info->protocol;
    }

    bpf_map_update_elem(&pending_connects, &id, &e, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct event *pend = (struct event *)bpf_map_lookup_elem(&pending_connects, &id);

    if (!pend) {
        return 0;
    }

    long ret = ctx->ret;
    pend->result = ret;

    if (pend->result == 0 || pend->result == -115) {
        struct flow_key fkey = {};
        fkey.family = pend->family;
        fkey.remote_port = pend->remote_port;
        fkey.protocol = pend->protocol;
        __builtin_memcpy(fkey.remote_addr, pend->remote_addr, sizeof(fkey.remote_addr));
        struct flow_metrics *m = bpf_map_lookup_elem(&flow_mtr, &fkey);
        if (!m) {
            struct flow_metrics zero = {};
            bpf_map_update_elem(&flow_mtr, &fkey, &zero, BPF_NOEXIST);
        }
    }

    bpf_ringbuf_output(&events, pend, sizeof(*pend), 0);
    bpf_map_delete_elem(&pending_connects, &id);

    return 0;
}

/*
struct tracepoint__syscalls__sys_enter_socket {
    unsigned long long common_tp_fields;
    int __syscall_nr;
    long family;
    long type;
    long protocol;
};
*/

SEC("tp/syscalls/sys_enter_socket")
int handle_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!bpf_map_lookup_elem(&allowed_pids, &pid)) {
        return 0;
    }

    struct socket_info info = {};

    info.family = ctx->args[0];
    info.type = ctx->args[1];
    info.protocol = ctx->args[2];

    if (info.family != AF_INET && info.family != AF_INET6) {
        return 0;
    }

    int base_type = info.type & 0xf;

    if (info.protocol == 0) {
        if (base_type == SOCK_STREAM) {
            info.protocol = IPPROTO_TCP; // 6
        } else if (base_type == SOCK_DGRAM) {
            info.protocol = IPPROTO_UDP; // 17
        }
    }

    bpf_map_update_elem(&tmp_sockets, &id, &info, BPF_ANY);

    return 0;
}

/*
struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    long int id;
    long int ret;
    char __data[0];
};
*/

SEC("tp/syscalls/sys_exit_socket")
int handle_socket_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 id = bpf_get_current_pid_tgid();

    struct socket_info *info = bpf_map_lookup_elem(&tmp_sockets, &id);

    if (!info) {
        return 0;
    }

    __u32 pid = id >> 32;
    int fd = (int)ctx->ret;

    if (fd >= 0) {
        __u64 key = ((__u64)pid << 32) | (__u32)fd;

        bpf_map_update_elem(&sockets, &key, info, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_sockets, &id);

    return 0;
}

/*
struct trace_event_raw_sys_enter_close {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    int __syscall_nr;
    long fd;
};
*/

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx) {
    int fd = ctx->args[0];
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u64 key = ((__u64)pid << 32) | (__u32)fd;

    bpf_map_delete_elem(&sockets, &key);
    return 0;
}

// SEC("tp/syscalls/sys_enter_sendto")
// int handle_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
//     void *addr = (void *)ctx->args[4];
//     if (!addr) {
//         return 0;
//     }
//
//     __u64 id = bpf_get_current_pid_tgid();
//     __u32 pid = id >> 32;
//
//     if (!bpf_map_lookup_elem(&allowed_pids, &pid)) {
//         return 0;
//     }
//
//     int fd = (int)ctx->args[0];
//     __u64 key = ((__u64)pid << 32) | (__u32)fd;
//     struct socket_info *info = bpf_map_lookup_elem(&sockets, &key);
//
//     if (!info || info->protocol != IPPROTO_UDP) {
//         return 0;
//     }
//
//     struct event e = {};
//     if (parse_user_sockaddr(addr, &e) < 0) {
//         return 0;
//     }
//
//     e.pid = pid;
//     e.tid = (__u32)id;
//     e.fd = fd;
//     e.type = info->type;
//     e.protocol = IPPROTO_UDP;
//     bpf_get_current_comm(e.comm, sizeof(e.comm));
//     bpf_map_update_elem(&pending_sendto, &id, &e, BPF_ANY);
//     return 0;
// }
//
// SEC("tp/syscalls/sys_exit_sendto")
// int handle_exit_sendto(struct trace_event_raw_sys_exit *ctx)
// {
//     __u64 id = bpf_get_current_pid_tgid();
//
//     struct event *e = bpf_map_lookup_elem(&pending_sendto, &id);
//
//     if (!e) {
//         return 0;
//     }
//
//     long ret = ctx->ret;
//
//     if (ret >= 0) {
//         e->result = 0;
//         struct flow_key fkey = {};
//         fkey.family = e->family;
//         fkey.remote_port = e->remote_port;
//         __builtin_memcpy(fkey.remote_addr, e->remote_addr, sizeof(fkey.remote_addr));
//
//         struct flow_metrics *m = bpf_map_lookup_elem(&flow_mtr, &fkey);
//
//         if (!m) {
//             struct flow_metrics zero = {};
//             bpf_map_update_elem(&flow_mtr, &fkey, &zero, BPF_NOEXIST);}
//     } else {
//         e->result = (int)ret;
//     }
//     bpf_ringbuf_output(&events, e, sizeof(*e), 0);
//     bpf_map_delete_elem(&pending_sendto, &id);
//     return 0;
// }
//
// SEC("tp/syscalls/sys_enter_sendmsg")
// int handle_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
//     __u64 id = bpf_get_current_pid_tgid();
//     __u32 pid = id >> 32;
//
//     if (!bpf_map_lookup_elem(&allowed_pids, &pid)) {
//         return 0;
//     }
//
//     int fd = (int)ctx->args[0];
//     __u64 key = ((__u64)pid << 32) | (__u32)fd;
//
//     struct socket_info *info = bpf_map_lookup_elem(&sockets, &key);
//
//     if (!info || info->protocol != IPPROTO_UDP) {
//         return 0;
//     }
//
//     struct msghdr msg = {};
//
//     if (bpf_probe_read_user(&msg, sizeof(msg), (void *)ctx->args[1]) != 0) {
//         return 0;
//     }
//
//     if (!msg.msg_name) {
//         return 0;
//     }
//
//     struct event e = {};
//
//     if (parse_user_sockaddr(msg.msg_name, &e) < 0) {
//         return 0;
//     }
//
//     e.pid = pid;
//     e.tid = (__u32)id;
//     e.fd = fd;
//     e.type = info->type;
//     e.protocol = IPPROTO_UDP;
//
//     bpf_get_current_comm(e.comm, sizeof(e.comm));
//
//     bpf_map_update_elem(&pending_sendmsg, &id, &e, BPF_ANY);
//
//     return 0;
// }
//
// SEC("tp/syscalls/sys_exit_sendmsg")
// int handle_exit_sendmsg(struct trace_event_raw_sys_exit *ctx)
// {
//     __u64 id = bpf_get_current_pid_tgid();
//
//     struct event *e = bpf_map_lookup_elem(&pending_sendmsg, &id);
//
//     if (!e) {
//         return 0;
//     }
//
//     long ret = ctx->ret;
//
//     if (ret >= 0) {
//         e->result = 0;
//
//         struct flow_key fkey = {};
//         fkey.family = e->family;
//         fkey.remote_port = e->remote_port;
//
//         __builtin_memcpy(fkey.remote_addr, e->remote_addr, sizeof(fkey.remote_addr));
//
//         struct flow_metrics zero = {};
//
//         long added = bpf_map_update_elem(&flow_mtr, &fkey, &zero, BPF_NOEXIST );
//
//         if (added == 0) {
//             bpf_ringbuf_output(&events, e, sizeof(*e), 0);
//         }
//     } else {
//         e->result = (int)ret;
//     }
//
//     bpf_map_delete_elem(&pending_sendmsg, &id);
//
//     return 0;
// }

static int udp_check(struct msghdr *msg) {
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;

    if (!bpf_map_lookup_elem(&allowed_pids, &pid)) {
        return 0;
    }

    void *addr = BPF_CORE_READ(msg, msg_name);

    if (!addr) {
        return 0;
    }

    struct flow_key key = {};
    key.protocol = IPPROTO_UDP;

    if (bpf_probe_read_kernel(&key.family, sizeof(key.family), addr) < 0) {
        return 0;
    }

    if (key.family == AF_INET) {
        struct sockaddr_in addr4 = {};
        if (bpf_probe_read_kernel(&addr4, sizeof(addr4), addr) < 0) {
            return 0;
        }

        key.remote_port = bpf_ntohs(addr4.sin_port);

        __builtin_memcpy(key.remote_addr, &addr4.sin_addr, sizeof(addr4.sin_addr));
    } else if (key.family == AF_INET6) {
        struct sockaddr_in6 addr6 = {};
        if (bpf_probe_read_kernel(&addr6, sizeof(addr6), addr) < 0) {
            return 0;
        }

        key.remote_port = bpf_ntohs(addr6.sin6_port);

        __builtin_memcpy(key.remote_addr, &addr6.sin6_addr, sizeof(addr6.sin6_addr));
    } else {
        return 0;
    }

    struct flow_metrics zero = {};
    bpf_map_update_elem(&flow_mtr, &key, &zero, BPF_NOEXIST );

    return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(handle_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    udp_check(msg);
    return 0;
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(handle_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    udp_check(msg);
    return 0;
}

/*

struct __sk_buff {
    __u32 len;              Длина пакета
    __u32 pkt_type;         Тип пакета (например, PACKET_HOST, PACKET_BROADCAST)
    __u32 mark;             /* Метка пакета (skb->mark), можно читать и писать
    __u32 queue_mapping;    /* Очередь сетевой карты *
    __u32 protocol;         /* Протокол пакета (например, ETH_P_IP) в сетевом порядке байт *
    __u32 vlan_present;     /* Присутствует ли VLAN-тег *
    __u32 vlan_tci;         /* VLAN Tag Control Information *
    __u32 vlan_proto;       /* Протокол VLAN encapsulation *
    __u32 priority;         /* Приоритет для QoS/дисков *
    __u32 ingress_ifindex;  /* Индекс входящего сетевого интерфейса *
    __u32 ifindex;          /* Текущий индекс сетевого интерфейса *
    __u32 tc_index;         /* Индекс классификатора трафика (Traffic Control) *
    __u32 cb[5];            /* Control Buffer: 20 байт для хранения кастомных данных между eBPF-программами *
    __u32 hash;             /* Хэш пакета, вычисленный сетевой картой или ядром *
    __u32 tc_classid;       /* Идентификатор класса Traffic Control *
    __u32 data;             /* Указатель на начало данных пакета (полинейная часть) *
    __u32 data_end;         /* Указатель на конец данных пакета *
    __u32 napi_id;          /* Идентификатор NAPI-контекста *

    /* Доступно в более новых версиях ядра Linux *
    __u32 family;           /* Семейство протоколов (AF_INET / AF_INET6) *
    __u32 remote_ip4;       /* Удаленный IPv4-адрес (для BPF_PROG_TYPE_CGROUP_SKB) *
    __u32 local_ip4;        /* Локальный IPv4-адрес *
    __u32 remote_ip6[4];    /* Удаленный IPv6-адрес *
    __u32 local_ip6[4];     /* Локальный IPv6-адрес *
    __u32 remote_port;      /* Удаленный порт (в сетевом порядке байт) *
    __u32 local_port;       /* Локальный порт *
    __u32 data_meta;        /* Указатель на метаданные перед началом пакета (для связи XDP -> TC) *

    struct bpf_flow_keys *flow_keys; /* Выделенные ключи потока (информация о L3/L4) *
    __u64 tstamp;           /* Временная метка пакета (ktime) *
    __u32 wire_len;         /* Длина пакета "на проводе" (включая обрезанные L2-данные) *
    __u32 gso_segs;         /* Количество сегментов при GSO (Generic Segmentation Offload) *
    struct bpf_sock *sk;    /* Указатель на связанный сокет (если он есть) *
    __u32 gso_size;         /* Размер сегмента GSO *
    __u8  tstamp_type;      /* Тип временной метки *
    __u8  hwtstamp;         /* Аппаратная временная метка
};

*/

static int traffic_analyze(struct __sk_buff *skb, bool tx_rx) {
    struct flow_key fkey = {};
    __u16 eth_proto = bpf_ntohs((__u16)skb->protocol);
    struct read_port {
        __u16 sport;
        __u16 dport;
    };

    if (eth_proto == ETH_P_IP) {
        struct iphdr ip4 = {};
        struct read_port ports;
        if (bpf_skb_load_bytes_relative(skb, 0, &ip4, sizeof(ip4), BPF_HDR_START_NET) < 0) {
            return TCX_NEXT;
        }

        if (ip4.protocol != IPPROTO_TCP && ip4.protocol != IPPROTO_UDP) {
                return TCX_NEXT;
        }

        fkey.family = AF_INET;
        fkey.protocol = ip4.protocol;

        __u32 ip_hdr_len = ip4.ihl * 4;
        if (ip_hdr_len < sizeof(struct iphdr)) {
            return TCX_NEXT;
        }

        int ret = bpf_skb_load_bytes_relative(skb, ip_hdr_len, &ports, sizeof(ports), BPF_HDR_START_NET);
        
        if (ret != 0) {
            return TCX_NEXT;
        }

        if (tx_rx) {
            __builtin_memcpy(fkey.remote_addr, &ip4.daddr, sizeof(ip4.daddr));
            fkey.remote_port = bpf_ntohs(ports.dport);
        } else {
            __builtin_memcpy(fkey.remote_addr, &ip4.saddr, sizeof(ip4.saddr));
            fkey.remote_port = bpf_ntohs(ports.sport);
        }
    } else if (eth_proto == ETH_P_IPV6) {
        struct ipv6hdr ip6 = {};
        struct read_port ports;
        if (bpf_skb_load_bytes_relative(skb, 0, &ip6, sizeof(ip6), BPF_HDR_START_NET) < 0) {
            return TCX_NEXT;
        }

        fkey.family = AF_INET6;

         if (ip6.nexthdr != IPPROTO_TCP && ip6.nexthdr != IPPROTO_UDP) {
             return TCX_NEXT;
         }

        fkey.protocol = ip6.nexthdr;

        int ret = bpf_skb_load_bytes_relative(skb, sizeof(struct ipv6hdr), &ports, sizeof(ports), BPF_HDR_START_NET);

        if (ret != 0) {
            return TCX_NEXT;
        }

        if (tx_rx) {
            __builtin_memcpy(fkey.remote_addr, &ip6.daddr, sizeof(ip6.daddr));
            fkey.remote_port = bpf_ntohs(ports.dport);
        } else {
            __builtin_memcpy(fkey.remote_addr, &ip6.saddr, sizeof(ip6.saddr));
            fkey.remote_port = bpf_ntohs(ports.sport);
        }
    } else {
        return TCX_NEXT;
    }

    struct flow_metrics *m = bpf_map_lookup_elem(&flow_mtr, &fkey);

    if (!m) {
        return TCX_NEXT;
    }

    __u64 len = skb->len;
    __u64 packets = skb->gso_segs;
    if (packets == 0) {
        packets = 1;
    }

    if (tx_rx) {
        __sync_fetch_and_add(&m->tx_bytes, len);
        __sync_fetch_and_add(&m->tx_packets, packets);
    } else {
        __sync_fetch_and_add(&m->rx_bytes, len);
        __sync_fetch_and_add(&m->rx_packets, packets);
    }

    return TCX_NEXT;
}

SEC("tcx/egress")
int handle_egress(struct __sk_buff *skb) {
    return traffic_analyze(skb, true);
}

SEC("tcx/ingress")
int handle_ingress(struct __sk_buff *skb) {
    return traffic_analyze(skb, false);
}