# FlowRay v0.5.0

Linux application network activity analyzer.

FlowRay analyzes Linux network sockets and maps them back to the processes that own them.

The project currently provides two monitoring backends:

- classic socket monitoring using Linux socket diagnostics;
- an experimental eBPF backend.

## Requirements

### Linux

The eBPF backend requires:

- Linux 6.6+
- kernel BTF at `/sys/kernel/btf/vmlinux`
- sudo access
- 512 MiB RAM to run flowray (recommended)

> Linux 6.6+ is required because flowray uses TCX for packet accounting.

### Arch Linux

Install dependencies:

```
sudo pacman -S base-devel git cmake clang bpf
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

---

### Attention (eBPF build files)

If you want to generate from source, keep in mind, for eBPF need to be generated two files:
- ebpf/vmlinux.h - generated from kernel BTF
- ebpf/ebpf_connect.skel.h - generated from the compiled .bpf.o

They are generated automatically by CMakeLists.txt during the build.

## Example

Analyze Discord network activity via a socket:

```bash
./flowray --name Discord --tree --detail
```

or live monitoring:

```bash
./flowray --name Discord --tree --detail --live
```

![FlowRay live mode](docs/live.png)

## Usage

### Target selection

FlowRay requires a target selected either by PID or process name.

```text
flowray (--pid PID | --name NAME) [options]
```

#### `--pid (-p)`

Analyze sockets belonging to the specified process.

```bash
./flowray --pid 12345
```

#### `--name (-n)`

Analyze processes by their process name.

> Unlike --pid, this option may select multiple processes.

```bash
./flowray --name Discord
```

### Additional flags

#### `--tree (-t)`

Include descendant processes in the analysis.

#### `--detail (-d)`

Show additional socket information, including PID and inode.

#### `--live (-l)`

Continuously monitor socket activity and track connection lifetime.

#### `--ebpf, -e`

Use the experimental eBPF backend.

> The eBPF backend is already event-driven, so `--live` is not required.

Run with sudo:

```bash
sudo ./build/flowray --name Discord --tree --ebpf
```

or:

```bash
sudo ./build/flowray --pid 12345 --ebpf
```

example output:

```
TRAFFIC 192.168.0.1:53 | RX: 9506 bytes / 35 packets | TX: 1175 bytes / 14 packets
TRAFFIC 13.249.8.75:443 | RX: 2950548 bytes / 792 packets | TX: 41844 bytes / 700 packets
```

## FAQ

NETLINK_SOCK_DIAG fails after a system/kernel update

> If the Linux kernel or kernel modules were updated while the system was running, the currently running kernel may no longer match the modules installed on disk. Reboot the system and try FlowRay again.