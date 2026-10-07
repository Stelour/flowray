#ifndef FLOWRAY_OUTPUT_FTXUI_H
#define FLOWRAY_OUTPUT_FTXUI_H

#include <vector>
#include "data.h"

status_msg output_table_socket_live(std::vector<std::uint32_t> pids,
    bool pid_tree, bool pid_detail, const std::string& proc_name);

status_msg output_ebpf_live(const std::vector<std::uint32_t>& pids, const std::string& proc_name, bool pid_tree, bool pid_detail, std::uint64_t ring_buf_size);

#endif //FLOWRAY_OUTPUT_FTXUI_H
