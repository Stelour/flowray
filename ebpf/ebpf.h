#ifndef FLOWRAY_EBPF_H
#define FLOWRAY_EBPF_H

#define FLOWRAY_COMM_LEN 16
#define FLOWRAY_ADDR_LEN 16

#define AF_INET 2
#define AF_INET6 10

struct event {
    unsigned int pid;
    unsigned int tid;

    int fd;

    unsigned short family;
    unsigned short remote_port;

    unsigned char remote_addr[FLOWRAY_ADDR_LEN];

    char comm[FLOWRAY_COMM_LEN];

    int result;

    int type;
    int protocol;
};

struct socket_info {
    int family;
    int type;
    int protocol;
};

struct flow_key {
    unsigned short family;
    unsigned short remote_port;
    unsigned char remote_addr[FLOWRAY_ADDR_LEN];
    unsigned int protocol;
};

struct flow_metrics {
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned long long rx_packets;
    unsigned long long tx_packets;
};

#endif //FLOWRAY_EBPF_H
