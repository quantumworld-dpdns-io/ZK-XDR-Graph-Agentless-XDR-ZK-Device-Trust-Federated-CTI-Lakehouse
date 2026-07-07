/*
 * ZK-XDR Graph eBPF Network Collector
 * 
 * Collects network connection events (TCP/UDP) from the kernel
 * using eBPF kprobes on inet_connect, inet_accept, etc.
 * 
 * This is a stub implementation for portfolio demonstration.
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

typedef struct {
    char event_id[64];
    char timestamp[32];
    pid_t pid;
    char comm[256];
    char saddr[16];
    char daddr[16];
    uint16_t sport;
    uint16_t dport;
    char protocol[8];
    int bytes_sent;
    int bytes_received;
} network_event_t;

static volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

void simulate_network_events() {
    network_event_t event;
    static int event_counter = 0;
    
    const char* suspicious_connections[] = {
        "203.0.113.42", "198.51.100.66", "192.0.2.123",
        NULL
    };
    
    memset(&event, 0, sizeof(event));
    
    snprintf(event.event_id, sizeof(event.event_id), "ebpf_net_%d_%d",
             getpid(), event_counter++);
    
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(event.timestamp, sizeof(event.timestamp), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    
    event.pid = 1000 + rand() % 30000;
    strncpy(event.comm, "curl", sizeof(event.comm) - 1);
    
    int is_suspicious = rand() % 15 == 0; // ~7% suspicious
    
    if (is_suspicious) {
        int idx = rand() % 3;
        strncpy(event.daddr, suspicious_connections[idx], sizeof(event.daddr) - 1);
        strncpy(event.saddr, "192.168.1.100", sizeof(event.saddr) - 1);
    } else {
        // Normal internal or well-known IPs
        int idx = rand() % 3;
        const char* normal_ips[] = {"10.0.0.1", "172.16.0.1", "8.8.8.8"};
        strncpy(event.daddr, normal_ips[idx], sizeof(event.daddr) - 1);
        strncpy(event.saddr, "192.168.1.100", sizeof(event.saddr) - 1);
    }
    
    event.sport = 1024 + rand() % 64511;
    event.dport = is_suspicious ? (4444 + rand() % 100) : (80 + rand() % 443);
    strncpy(event.protocol, "TCP", sizeof(event.protocol) - 1);
    event.bytes_sent = rand() % 10000;
    event.bytes_received = rand() % 50000;
    
    char json[MAX_EVENT_SIZE];
    snprintf(json, sizeof(json),
        "{\"event_id\":\"%s\",\"timestamp\":\"%s\",\"source\":\"ebpf\","
        "\"event_type\":\"endpoint.network.%s\",\"category\":\"network\","
        "\"severity\":\"%s\",\"confidence\":80,\"risk_score\":%d,"
        "\"source_ip\":\"%s\",\"dest_ip\":\"%s\","
        "}",
        event.event_id,
        event.timestamp,
        is_suspicious ? "suspicious_connection" : "connection_established",
        is_suspicious ? "high" : "info",
        is_suspicious ? 650 : 100,
        event.saddr,
        event.daddr
    );
    
    printf("[eBPF Network] %s\n", json);
}

int main(int argc, char* argv[]) {
    printf("ZK-XDR Graph eBPF Network Collector v0.1.0\n");
    printf("Collecting network events from kernel...\n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    srand(time(NULL));
    
    int interval_ms = 3000;
    if (argc > 1) {
        interval_ms = atoi(argv[1]);
    }
    
    printf("Event interval: %dms\n", interval_ms);
    printf("Press Ctrl+C to stop\n\n");
    
    while (running) {
        simulate_network_events();
        usleep(interval_ms * 1000);
    }
    
    printf("\nNetwork collector stopped.\n");
    return 0;
}
