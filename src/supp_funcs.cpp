#include "../headers/supp_funcs.h"

#include <cstdint>
#include <string>
#include <netinet/in.h>

std::string state_to_string(std::uint8_t state) {
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

std::string protocol_to_string(int protocol) {
    switch (protocol) {
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_UDP: return "UDP";
    default: return "UNKNOWN";
    }
}

std::string family_to_string(int family) {
    switch (family) {
    case AF_INET: return "IPv4";
    case AF_INET6: return "IPv6";
    default: return "UNKNOWN";
    }
}

std::string result_to_string(int result) {
    if (result == 0) {
        return "SUCCESS";
    }
    if (result == -EINPROGRESS) {
        return "PENDING";
    }
    return "FAILED";
};

std::string dns_type_to_string(std::uint16_t type) {
    switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 64: return "SVCB";
    case 65: return "HTTPS";
    case 255: return "ANY";
    default: return "TYPE" + std::to_string(type);
    }
}