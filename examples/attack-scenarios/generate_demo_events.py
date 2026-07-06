#!/usr/bin/env python3
"""Generate demo XDR events for the ZK-XDR Graph platform."""

import json
import time
import uuid
import redis
import random
from datetime import datetime, timezone

def generate_events():
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)

    events = [
        {
            "source": "ddi",
            "event_type": "dns.query.suspicious",
            "data": {
                "query": "strange-domain.example",
                "src_ip": "10.10.20.42",
                "device_id": "dev_iot_camera_042",
                "domain": "strange-domain.example",
                "network_segment": "finance-iot"
            }
        },
        {
            "source": "zk",
            "event_type": "zk.device.attestation.failed",
            "data": {
                "device_id": "dev_iot_camera_042",
                "attestation_result": "failed",
                "trust_score_delta": -25,
                "proof_system": "risc0",
                "circuit_type": "device_attestation"
            }
        },
        {
            "source": "waf",
            "event_type": "waf.anomaly.detected",
            "data": {
                "path": "/api/v1/auth/login",
                "method": "POST",
                "src_ip": "203.0.113.42",
                "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
                "rate": 150,
                "threshold": 100,
                "anomaly_type": "credential_stuffing"
            }
        },
        {
            "source": "mail",
            "event_type": "email.phishing.detected",
            "data": {
                "sender": "phishing@suspicious-domain.example",
                "subject": "Urgent: Verify your account",
                "phishing_type": "quishing",
                "has_qr_code": True,
                "recipient_count": 45,
                "campaign_id": "quishing_finance_001"
            }
        },
        {
            "source": "endpoint",
            "event_type": "endpoint.process.suspicious",
            "data": {
                "process_name": "mimikatz.exe",
                "pid": 4567,
                "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                "device_id": "dev_workstation_003",
                "user": "finance_admin",
                "hash": "sha256:abc123..."
            }
        }
    ]

    for event in events:
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        stream_event = {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": event["source"],
            "data": json.dumps(event["data"])
        }

        r.xadd("xdr.events", stream_event)
        print(f"Generated {event['event_type']} event: {event_id}")

    print(f"\nGenerated {len(events)} demo events")

if __name__ == "__main__":
    generate_events()
