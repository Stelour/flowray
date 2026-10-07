# flowray v0.6.0

Linux application network activity analyzer.

## About

FlowRay analyzes the network activity of running Linux applications. It shows remote addresses, ports, protocols, and traffic counters, along with connection events. It also logs outgoing UDP DNS queries sent to port 53.

Select an application by PID or process name and optionally include its descendant processes. View its activity in an interactive terminal interface or stdout, and export traffic and connection data to JSON.

The default eBPF backend provides live traffic monitoring and event logs. The socket diagnostics backend offers an alternative for inspecting sockets and their owning processes.

## Quick start

Analyze your browser traffic:

```bash
sudo ./build/flowray --name zen --tree
```

![fxtui_ebpf.png](docs/fxtui_ebpf.png)

or socket backend:

```bash
./build/flowray --name discord --tree --socket
```

![fxtui_socket.png](docs/fxtui_socket.png)

## Requirements

### Build dependencies

The eBPF backend requires:

- kernel BTF at `/sys/kernel/btf/vmlinux`
- CMake
- Clang
- bpftool
- libbpf
- pkg-config
- nlohmann/json

> CMake downloads CLI11 and FTXUI during configuration, so an internet connection is required.

### Runtime requirements

The eBPF backend requires:
- Linux with eBPF support
- cgroup v2 mounted at `/sys/fs/cgroup`
- Kernel BTF at `/sys/kernel/btf/vmlinux`
- Root privileges

The socket backend usually works without root.

### Arch Linux

Install dependencies:

```
sudo pacman -S --needed base-devel git cmake clang bpf libbpf nlohmann-json
```

## Build

Clone and build:

```bash
git clone https://github.com/Stelour/flowray.git
cd flowray

cmake -S . -B build
cmake --build build
```

And start using it:

```bash
./build/flowray --help
```

CMake automatically generates:

- `ebpf/vmlinux.h`
- `ebpf/ebpf_connect.bpf.o`
- `ebpf/ebpf_connect.skel.h`

## Usage

FlowRay requires a target selected either by PID or process name.

```text
flowray (--pid PID | --name NAME) [options]
```

### Target selection

#### `--pid, -p PID`

Analyze a process by PID.

```bash
sudo ./build/flowray --pid 12345
```

#### `--name, -n NAME`

Analyze all processes matching the specified process name.

```bash
sudo ./build/flowray --name Discord
```

> `--name` performs a case-insensitive substring match against Linux process names from `/proc/<pid>/comm`. It may select multiple processes.

#### Additional options (CLI `--help`)

```
FlowRay - linux application network activity analyzer


./flowray [OPTIONS]


OPTIONS:
  -h,     --help              Print this help message and exit
  -p,     --pid UINT Excludes: --name 
                              Analyze a process by PID
  -n,     --name TEXT Excludes: --pid 
                              Analyze all processes with the specified name
  -t,     --tree              Include descendant processes in the analysis
  -d,     --detail            Show additional connection details
  -l,     --live Needs: --socket 
                              Continuously monitor socket state changes
  -s,     --socket Excludes: --ring-buffer-size 
                              Use the classic socket diagnostics backend instead of eBPF
          --stdout            Print output to stdout instead of using the TUI
          --ring-buffer-size UINT Excludes: --socket 
                              Set the eBPF event ring buffer size in KiB (power of two, min
                              256)
  -e,     --export TEXT       Export monitoring data to a JSON file         
```

**Additionally**:

- `--pid` and `--name` are mutually exclusive.
- `--live (-l)` option is only available with the classic socket backend.
- `--ring-buffer-size` defaults to `256` KiB. It must be a power of two and at least `256`. This option cannot be used with `--socket`.

### Examples

Print traffic, connection events, and DNS queries to stdout:

```bash
sudo ./build/flowray --name discord --tree --stdout
```

Continuously print socket diagnostics:

```bash
./build/flowray --name discord --socket --live --stdout
```

Export monitoring data:

```bash
sudo ./build/flowray --name discord --tree --export traffic.json
```

The export file is replaced with an updated snapshot during live monitoring. DNS query logs are currently displayed in the interface and stdout, but are not included in JSON exports.

Use a larger connection event ring buffer:

```bash
sudo ./build/flowray --name discord --ring-buffer-size 1024
```

## FAQ

flowray via backend sockets fails after a system/kernel update

> If the Linux kernel or kernel modules were updated while the system was running, the currently running kernel may no longer match the modules installed on disk. Reboot the system and try FlowRay again.

eBPF fails to start, check that:

- FlowRay is running with root privileges.
- `/sys/kernel/btf/vmlinux` exists.
- cgroup v2 is mounted at `/sys/fs/cgroup`.
- The kernel supports the required BPF hooks.
- System security policy permits BPF loading and attachment.

Read the preceding libbpf error messages for the specific failure.