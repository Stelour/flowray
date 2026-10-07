cmake_minimum_required(VERSION 4.2)
project(
        flowray
        VERSION 1.0.0
        DESCRIPTION "Linux application network activity analyzer"
        LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 26)

include(FetchContent)

FetchContent_Declare(
        CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.7.2
        GIT_SHALLOW TRUE
)

FetchContent_Declare(
        ftxui
        GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI.git
        GIT_TAG v7.0.3
        GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(CLI11 ftxui)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)

set(EBPF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ebpf)

find_program(CLANG_EXECUTABLE
        NAMES clang
        REQUIRED
)

find_program(BPFTOOL_EXECUTABLE
        NAMES bpftool
        REQUIRED
)

if(NOT EXISTS "/sys/kernel/btf/vmlinux")
    message(FATAL_ERROR "Kernel BTF not found at /sys/kernel/btf/vmlinux")
endif()

add_custom_command(
        OUTPUT ${EBPF_DIR}/vmlinux.h

        COMMAND /bin/sh -c
        "\"${BPFTOOL_EXECUTABLE}\" btf dump file /sys/kernel/btf/vmlinux format c > \"${EBPF_DIR}/vmlinux.h\""

        DEPENDS /sys/kernel/btf/vmlinux

        COMMENT "Generating vmlinux.h from kernel BTF"
        VERBATIM
)

add_custom_command(
        OUTPUT ${EBPF_DIR}/ebpf_connect.skel.h
        BYPRODUCTS ${EBPF_DIR}/ebpf_connect.bpf.o

        COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf -I${EBPF_DIR}
        -c ${EBPF_DIR}/ebpf_connect.bpf.c -o ${EBPF_DIR}/ebpf_connect.bpf.o

        COMMAND /bin/sh -c
        "\"${BPFTOOL_EXECUTABLE}\" gen skeleton \"${EBPF_DIR}/ebpf_connect.bpf.o\" > \"${EBPF_DIR}/ebpf_connect.skel.h\""

        DEPENDS ${EBPF_DIR}/ebpf_connect.bpf.c ${EBPF_DIR}/ebpf.h ${EBPF_DIR}/vmlinux.h

        COMMENT "Building eBPF program"
        VERBATIM
)

add_custom_target(ebpf_build
        DEPENDS ${EBPF_DIR}/ebpf_connect.skel.h
)

add_executable(flowray main.cpp
        src/pid.cpp
        src/socket.cpp
        headers/socket.h
        src/pid_child.cpp
        src/output.cpp
        headers/pid.h
        headers/output.h
        headers/data.h
        src/proc_name.cpp
        headers/proc_name.h
        ebpf/ebpf.h
        ebpf/ebpf_monitor.cpp
        ebpf/ebpf_connect.skel.h
        src/output_ftxui.cpp
        headers/output_ftxui.h
)

target_link_libraries(flowray PRIVATE CLI11::CLI11 PkgConfig::LIBBPF ftxui::screen ftxui::dom ftxui::component)

target_compile_options(flowray PRIVATE
        -Wall
        -Wextra
        -Wpedantic
)

add_dependencies(flowray ebpf_build)