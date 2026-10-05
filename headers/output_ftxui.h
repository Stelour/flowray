#ifndef FLOWRAY_OUTPUT_FTXUI_H
#define FLOWRAY_OUTPUT_FTXUI_H

#include <vector>
#include "data.h"

status_msg output_table_socket_live(std::vector<std::uint32_t> pids,
    bool pid_tree, bool pid_detail, const std::string& proc_name);

#endif //FLOWRAY_OUTPUT_FTXUI_H
