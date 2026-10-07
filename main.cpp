#include "headers/pid.h"
#include "headers/proc_name.h"
#include "ebpf/ebpf_monitor.h"
#include "headers/output_ftxui.h"

#include <CLI/CLI.hpp>
#include <iostream>

int main(int argc, char* argv[]) {
    CLI::App app{"FlowRay - linux application network activity analyzer"};

    std::uint32_t pid{};
    CLI::Option *op_pid = app.add_option(
        "--pid,-p",
        pid,
        "Analyze a process by PID"
        );

    std::string proc_name;
    CLI::Option *op_name = app.add_option(
        "--name,-n",
        proc_name,
        "Analyze all processes with the specified name"
        );

    bool pid_tree = false;
    app.add_flag(
        "--tree,-t",
        pid_tree,
        "Include descendant processes in the analysis"
        );

    bool pid_detail = false;
    app.add_flag(
        "--detail,-d",
        pid_detail,
        "Show additional connection details"
        );

    bool proc_live = false;
    CLI::Option *op_live = app.add_flag(
        "--live,-l",
        proc_live,
        "Continuously monitor socket state changes"
        );

    // bool ebpf = false;
    // CLI::Option *op_ebpf = app.add_flag(
    //     "--ebpf,-e",
    //     ebpf,
    //     "ebpf"
    //     );

    bool is_socket = false;
    CLI::Option* op_socket = app.add_flag(
        "--socket,-s",
        is_socket,
        "Use the classic socket diagnostics backend instead of eBPF"
        );

    bool print_term = false;
    app.add_flag(
        "--stdout",
        print_term,
        "Print output to stdout instead of using the TUI"
        );

    std::uint64_t ring_buf_size = 256;
    CLI::Option* op_ring_size = app.add_option(
        "--ring-buffer-size",
        ring_buf_size,
        "Set the eBPF event ring buffer size in KiB (power of two, min 256)"
        );

    op_pid->excludes(op_name);
    op_name->excludes(op_pid);
    op_ring_size->excludes(op_socket);
    op_live->needs(op_socket);

    CLI11_PARSE(app, argc, argv);

    if (!(*op_pid || *op_name)) {
        std::cout << app.help();
        return 0;
    }

    ring_buf_size *= 1024;
    if (ring_buf_size < 256 * 1024 || (ring_buf_size & (ring_buf_size - 1)) != 0) {
        std::cerr << "ERROR: --ring-buf-size incorrect num" << std::endl;
        return 1;
    }

    std::vector<std::uint32_t> pids;
    if (*op_name) {
        pids = find_pids_by_name(proc_name);
        if (pids.empty()) {
            std::cerr << "ERROR: process " << proc_name << " not found" << std::endl;
            return 1;
        }
    } else if (*op_pid) {
        pids = {pid};
    }

    if (pids.empty()) {
        std::cerr << "ERROR: pid is clear" << std::endl;
        return 1;
    }

    if (is_socket) {
        if (start_pid(pids, pid_tree, pid_detail, proc_live, proc_name, print_term) != status_msg::success) {
            std::cerr << "ERROR: failed to start process pid " << std::endl;
            return 1;
        }
    } else {
        if (print_term) {
            if (ebpf_start(pids, proc_name, pid_tree, ring_buf_size) != 0) {
                std::cerr << "ERROR: failed to start ebpf " << std::endl;
                return 1;
            }
        } else {
            if (output_ebpf_live(pids, proc_name, pid_tree, pid_detail, ring_buf_size) != status_msg::success) {
                std::cerr << "ERROR: failed to start live ebpf " << std::endl;
                return 1;
            }
        }
    }

    return 0;
}