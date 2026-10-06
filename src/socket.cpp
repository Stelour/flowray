#include "../headers/socket.h"

#include <arpa/inet.h>
#include <cerrno>
#include <iostream>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <unordered_map>

struct DiagRequest {
    nlmsghdr nlh{};
    inet_diag_req_v2 req{};
};

static int send_req(int fd, DiagQuery socket_diag_query) {
    // send to Linux kernel.
    sockaddr_nl kernel_addr{};
    kernel_addr.nl_family = AF_NETLINK;
    kernel_addr.nl_pid = 0;
    kernel_addr.nl_groups = 0;

    // sock_diag msg
    DiagRequest req{};
    req.nlh.nlmsg_len = sizeof(req);
    req.nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.req.sdiag_family = socket_diag_query.family;
    req.req.sdiag_protocol = socket_diag_query.protocol;
    req.req.idiag_states = 0xFFFFFFFF;

    // buffer of msg
    iovec iov{};
    iov.iov_base = &req;
    iov.iov_len = sizeof(req);

    // desc
    msghdr msg{};
    msg.msg_name = &kernel_addr;
    msg.msg_namelen = sizeof(kernel_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    for (;;) {
        if (sendmsg(fd, &msg, 0) < 0) {
            if (errno == EINTR)
                continue;

            std::cerr << "ERROR: sendmsg" << std::endl;
            return 1;
        }
        return 0;
    }
}

static SocketInfo parse_diag(const inet_diag_msg *diag, DiagQuery socket_diag_query, const std::set<std::uint32_t>& pids) {
    SocketInfo socket{};

    // diag->idiag_family
    // diag->idiag_state
    // diag->id.idiag_sport
    // diag->id.idiag_dport
    // diag->id.idiag_src
    // diag->id.idiag_dst
    // diag->idiag_uid
    // diag->idiag_inode

    socket.pids = pids;
    socket.inode = diag->idiag_inode;
    socket.uid = diag->idiag_uid;
    socket.state = diag->idiag_state;

    socket.family = diag->idiag_family;
    socket.protocol = socket_diag_query.protocol;

    socket.local_port = ntohs(diag->id.idiag_sport);
    socket.remote_port = ntohs(diag->id.idiag_dport);

    char local_ip[INET6_ADDRSTRLEN]{};
    char remote_ip[INET6_ADDRSTRLEN]{};

    inet_ntop(
        diag->idiag_family,
        diag->id.idiag_src,
        local_ip,
        sizeof(local_ip)
    );

    inet_ntop(
        diag->idiag_family,
        diag->id.idiag_dst,
        remote_ip,
        sizeof(remote_ip)
    );

    socket.local_ip = local_ip;
    socket.remote_ip = remote_ip;

    return socket;
}

static int receive_response(int fd,
    const std::unordered_map<std::uint32_t, std::set<std::uint32_t>>& target_inodes,
    std::vector<SocketInfo>& sockets,
    DiagQuery socket_diag_query) {

    // alignas(nlmsghdr) char buffer[8192]{};
    std::vector<char> buffer;
    for (;;) {
        ssize_t msg_size;
        do {
            msg_size = recv(fd, nullptr, 0, MSG_PEEK | MSG_TRUNC);
        } while (msg_size < 0 && errno == EINTR);

        if (msg_size < 0) {
            std::cerr << "recv MSG_PEEK" << std::endl;
            return -1;
        }

        if (msg_size == 0) {
            return 0;
        }

        buffer.resize(static_cast<std::size_t>(msg_size));

        sockaddr_nl nladdr{};

        iovec iov{};
        iov.iov_base = buffer.data();
        iov.iov_len = buffer.size();

        msghdr msg{};
        msg.msg_name = &nladdr;
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        ssize_t ret = recvmsg(fd, &msg, 0);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }

            std::cerr << "recvmsg" << std::endl;
            return -1;
        }

        if (ret == 0) {
            return 0;
        }

        if (nladdr.nl_family != AF_NETLINK) {
            std::cerr << "!AF_NETLINK" << std::endl;
            return -1;
        }

        const auto *h = reinterpret_cast<const nlmsghdr*>(buffer.data());
        if (!NLMSG_OK(h, ret)) {
            std::cerr << "!NLMSG_OK" << std::endl;
            return -1;
        }

        // std::cout
        // << "received bytes: " << ret << '\n'
        // << "sender family: " << nladdr.nl_family << '\n'
        // << "nlmsg_len: " << h->nlmsg_len << '\n'
        // << "nlmsg_type: " << h->nlmsg_type << '\n'
        // << "nlmsg_flags: " << h->nlmsg_flags << '\n';
        // return 0;

        for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
            if (h->nlmsg_type == NLMSG_DONE) {
                return 0;
            }
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                    std::cerr << "NLMSG_ERROR" << std::endl;
                    return -1;
                }
                const auto *err = static_cast<const nlmsgerr *>(NLMSG_DATA(h));
                if (err->error == 0) {
                    continue;
                }
                errno = -err->error;
                std::perror("NLMSG_ERROR");
                return -1;
            }
            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                std::cerr << "unexpected type" << std::endl;
                return -1;
            }

            if (h->nlmsg_len < NLMSG_LENGTH(sizeof(inet_diag_msg))) {
                std::cerr << "Invalid inet_diag message length\n";
                continue;
            }

            const auto* diag = static_cast<const struct inet_diag_msg*>(NLMSG_DATA(h));
            const auto f = target_inodes.find(diag->idiag_inode);
            if (f == target_inodes.end()) {
                continue;
            }
            sockets.push_back(parse_diag(diag, socket_diag_query, f->second));
        }

    }
}

status_msg socket_req(
    const std::unordered_map<std::uint32_t, std::set<std::uint32_t>>& target_inodes,
    std::vector<SocketInfo>& sockets,
    DiagQuery socket_diag_query) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
    if (fd < 0) {
        std::perror("ERROR: failed to create sock_diag socket");
        return status_msg::error;
    }
    // std::cout << "sock_diag fd: " << fd << '\n';
    if (send_req(fd, socket_diag_query) != 0) {
        close(fd);
        return status_msg::error;
    }
    if (receive_response(fd, target_inodes, sockets, socket_diag_query) != 0) {
        close(fd);
        return status_msg::error;
    }
    close(fd);
    return status_msg::success;
}