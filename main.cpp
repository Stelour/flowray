#include "headers/pid.h"
#include "headers/proc_name.h"
#include "ebpf/ebpf_monitor.h"

#include <CLI/CLI.hpp>
#include <iostream>

/*
TODO: output with ncurses for --live; flag --ring-bufer-size; flag --socket; dns request;
*/

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
        "Show detailed socket information, including PID and inode"
        );

    bool proc_live = false;
    app.add_flag(
        "--live,-l",
        proc_live,
        "Monitor socket changes continuously"
        );

    bool ebpf = false;
    CLI::Option *op_ebpf = app.add_flag(
        "--ebpf,-e",
        ebpf,
        "ebpf"
        );

    bool live_print = false;
    app.add_flag(
        "--print,-r",
        live_print,
        "live_print"
        );

    op_pid->excludes(op_name);
    op_name->excludes(op_pid);

    CLI11_PARSE(app, argc, argv);

    if (!(*op_pid || *op_name || *op_ebpf)) {
        if (pid_tree || pid_detail) {
            std::cerr << "ERROR: --tree and --detail require --pid or --name" << std::endl;
            return -1;
        }
        std::cout << app.help();
        return 0;
    }

    if (*op_pid) {
        if (ebpf) {
            ebpf_start({pid}, proc_name, pid_tree);
        } else if (start_pid({pid}, pid_tree, pid_detail, proc_live, proc_name, live_print) != status_msg::success) {
            std::cerr << "ERROR: failed to start process pid " << std::endl;
            return -1;
        }
    } else if (*op_name) {
        auto pids = find_pids_by_name(proc_name);
        if (pids.empty()) {
            std::cerr << "ERROR: process " << proc_name << " not found" << std::endl;
            return -1;
        }
        if (ebpf) {
            ebpf_start(pids, proc_name, pid_tree);
        } else if (start_pid(pids, pid_tree, pid_detail, proc_live, proc_name, live_print) != status_msg::success) {
            std::cerr << "ERROR: failed to start process pid " << std::endl;
            return -1;
        }

    }

    return 0;
}