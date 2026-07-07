# ZK-XDR Graph eBPF Collectors

Kernel-level event collection using eBPF for agentless endpoint monitoring.

## Collectors

### process_collector.c
- Process creation/execution/termination events
- Uses tracepoints: sys_enter_execve, sched_process_exit
- Captures: PID, PPID, UID, command, executable path, exit code

### network_collector.c  
- TCP/UDP connection events
- Uses kprobes: inet_connect, inet_accept, udp_sendmsg
- Captures: source/dest IP, ports, bytes transferred

## Build

```bash
# Requires: clang, llvm, libbpf-dev, linux-headers
make

# Or individual collectors
gcc -o process_collector src/process_collector.c
gcc -o network_collector src/network_collector.c
```

## Usage

```bash
# Run with default 5s interval
./process_collector

# Custom interval (ms)
./process_collector 1000

# Network collector
./network_collector 3000
```

## Production Deployment

For production use, compile with BPF CO-RE support:
```bash
clang -O2 -target bpf -c src/process.bpf.c -o src/process.bpf.o
```

Requires:
- Linux kernel 5.4+
- CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y
- libbpf 1.0+
- bpftool for skeleton generation
