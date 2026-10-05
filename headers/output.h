#ifndef FLOWRAY_OUTPUT_H
#define FLOWRAY_OUTPUT_H

#include "data.h"

#include <vector>

void print_socket_info(std::span<SocketInfo> sockets, bool detail);
void print_process_info(std::span<ProcessInfo> processes);
void print_live_table(std::span<LiveSocket> sockets, bool detail);

#endif //FLOWRAY_OUTPUT_H
