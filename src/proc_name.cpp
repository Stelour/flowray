#include "../headers/proc_name.h"

#include <filesystem>
#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <cctype>
#include <iostream>

static bool is_number(const std::string& s) {
    if (s.empty()) return false;
    for (char const &c : s) {
        if (!std::isdigit(c)) return false;
    }
    return true;
}

std::string to_lower(std::string data) {
    std::transform(data.begin(), data.end(), data.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return data;
}

std::vector<std::uint32_t> find_pids_by_name(const std::string& proc_name) {
    std::vector<std::uint32_t> proc_pids;
    for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
        if (entry.is_directory()) {
            std::string folder_name = entry.path().filename().string();
            if (is_number(folder_name)) {
                std::ifstream file_pid_comm("/proc/" + folder_name + "/comm");
                if (!file_pid_comm) {
                    continue;
                }

                std::string process_name;
                std::getline(file_pid_comm, process_name);
                if (to_lower(process_name).find(to_lower(proc_name)) != std::string::npos) {
                    proc_pids.push_back(static_cast<uint32_t>(std::stoul(folder_name)));
                }
            }
        }
    }
    return proc_pids;
}