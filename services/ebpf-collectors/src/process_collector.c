/*
 * ZK-XDR Graph eBPF Process Collector
 * 
 * Collects process creation, execution, and termination events
 * from the Linux kernel using eBPF tracepoints.
 * 
 * This is a stub implementation for portfolio demonstration.
 * Full implementation requires Linux kernel 5.4+ and BPF CO-RE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_EVENT_SIZE 4096
#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define EVENT_STREAM "xdr:events"

typedef struct {
    char event_id[64];
    char timestamp[32];
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    char comm[256];
    char exe_path[1024];
    char cmdline[2048];
    int exit_code;
} process_event_t;

static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

/*
 * Simulate process events for demonstration.
 * In production, this would use:
 *   - bpf_tracepoint/syscalls/sys_enter_execve
 *   - bpf_tracepoint/sched/sched_process_exit
 *   - bpf_raw_tracepoint/raw_tracepoint/sched_process_fork
 */
void simulate_process_events() {
    process_event_t event;
    static int event_counter = 0;
    
    const char* suspicious_processes[] = {
        "nc", "ncat", "socat", "curl", "wget", "python", "perl",
        "bash", "sh", "dash", "ksh", "zsh",
        "nmap", "masscan", "zmap",
        NULL
    };
    
    const char* normal_processes[] = {
        "systemd", "sshd", "nginx", "postgres", "redis-server",
        "docker", "containerd", "kubelet",
        NULL
    };
    
    memset(&event, 0, sizeof(event));
    
    // Generate event ID
    snprintf(event.event_id, sizeof(event.event_id), "ebpf_proc_%d_%d", 
             getpid(), event_counter++);
    
    // Get timestamp
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(event.timestamp, sizeof(event.timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    // Simulate random process
    int is_suspicious = rand() % 10 == 0; // 10% chance of suspicious
    
    if (is_suspicious) {
        int idx = rand() % 13;
        strncpy(event.comm, suspicious_processes[idx], sizeof(event.comm) - 1);
        event.exit_code = 0;
    } else {
        int idx = rand() % 8;
        strncpy(event.comm, normal_processes[idx], sizeof(event.comm) - 1);
        event.exit_code = 0;
    }
    
    event.pid = 1000 + rand() % 30000;
    event.ppid = 1 + rand() % 1000;
    event.uid = rand() % 1000;
    
    // Format as JSON
    char json[MAX_EVENT_SIZE];
    snprintf(json, sizeof(json),
        "{\"event_id\":\"%s\",\"timestamp\":\"%s\",\"source\":\"ebpf\","
        "\"event_type\":\"endpoint.process.%s\",\"category\":\"endpoint\","
        "\"severity\":\"%s\",\"confidence\":85,\"risk_score\":%d,"
        "\"asset_id\":\"asset_001\",\"asset_name\":\"Workstation 003\","
        "\"mitre_tactic\":\"execution\",\"mitre_technique\":\"T1059\","
        "}", 
        event.event_id,
        event.timestamp,
        is_suspicious ? "suspicious" : "created",
        is_suspicious ? "high" : "info",
        is_suspicious ? 700 : 100
    );
    
    printf("[eBPF Process] %s\n", json);
}

int main(int argc, char* argv[]) {
    printf("ZK-XDR Graph eBPF Process Collector v0.1.0\n");
    printf("Collecting process events from kernel...\n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    srand(time(NULL));
    
    int interval_ms = 5000; // 5 seconds default
    if (argc > 1) {
        interval_ms = atoi(argv[1]);
    }
    
    printf("Event interval: %dms\n", interval_ms);
    printf("Press Ctrl+C to stop\n\n");
    
    while (running) {
        simulate_process_events();
        usleep(interval_ms * 1000);
    }
    
    printf("\nProcess collector stopped.\n");
    return 0;
}
