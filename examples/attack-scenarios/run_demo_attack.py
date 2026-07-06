#!/usr/bin/env python3
"""Run a complete demo attack scenario for the ZK-XDR Graph platform."""

import json
import time
import uuid
import redis
from datetime import datetime, timezone

def run_demo_attack():
    r = redis.Redis(host='localhost', port=6379, decode_responses=True)

    print("=" * 60)
    print("ZK-XDR Graph Platform - Demo Attack Scenario")
    print("=" * 60)
    print()
    print("Scenario: Coordinated Quishing + IoT Beaconing + API Abuse")
    print()

    steps = [
        {
            "step": 1,
            "description": "QR Phishing Email Sent",
            "source": "mail",
            "event_type": "email.phishing.detected",
            "data": {
                "sender": "hr-dept@company-secure.example",
                "subject": "Action Required: Update your benefits enrollment",
                "phishing_type": "quishing",
                "has_qr_code": True,
                "qr_url": "https://phish.example/benefits?token=abc123",
                "recipient_count": 45,
                "campaign_id": "quishing_benefits_2026"
            }
        },
        {
            "step": 2,
            "description": "User Scans QR Code",
            "source": "endpoint",
            "event_type": "user.phishing_interaction",
            "data": {
                "user_id": "user_finance_001",
                "action": "qr_scan",
                "url": "https://phish.example/benefits?token=abc123",
                "device_id": "dev_workstation_003",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        },
        {
            "step": 3,
            "description": "IoT Camera Queries Suspicious Domain",
            "source": "ddi",
            "event_type": "dns.query.suspicious",
            "data": {
                "query": "strange-domain.example",
                "src_ip": "10.10.20.42",
                "device_id": "dev_iot_camera_042",
                "domain": "strange-domain.example",
                "network_segment": "finance-iot",
                "domain_age_days": 3,
                "first_seen": True
            }
        },
        {
            "step": 4,
            "description": "API Credential Stuffing Detected",
            "source": "waf",
            "event_type": "waf.anomaly.detected",
            "data": {
                "path": "/api/v1/auth/login",
                "method": "POST",
                "src_ip": "203.0.113.42",
                "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
                "rate": 150,
                "threshold": 100,
                "anomaly_type": "credential_stuffing",
                "unique_users_targeted": 23,
                "related_asn": "AS15169"
            }
        },
        {
            "step": 5,
            "description": "ZK Attestation Expired",
            "source": "zk",
            "event_type": "zk.device.attestation.expired",
            "data": {
                "device_id": "dev_iot_camera_042",
                "attestation_result": "expired",
                "trust_score_delta": -30,
                "last_verified": "2026-07-01T00:00:00Z",
                "expired_duration_hours": 120,
                "proof_system": "risc0",
                "circuit_type": "device_attestation"
            }
        },
        {
            "step": 6,
            "description": "CTI Match Found",
            "source": "cti",
            "event_type": "cti.ioc_match",
            "data": {
                "indicator_id": "ioc_001",
                "type": "domain",
                "value": "strange-domain.example",
                "confidence": 82,
                "source": "federated_sme_cluster",
                "tlp": "amber",
                "tags": ["quishing", "c2", "iot"],
                "first_seen": "2026-07-01T00:00:00Z",
                "related_campaigns": ["quishing_benefits_2026"]
            }
        }
    ]

    incident_id = f"inc_{uuid.uuid4().hex[:12]}"

    for step in steps:
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        stream_event = {
            "event_id": event_id,
            "timestamp": timestamp,
            "source": step["source"],
            "data": json.dumps(step["data"])
        }

        r.xadd("xdr.events", stream_event)

        print(f"Step {step['step']}: {step['description']}")
        print(f"  Event ID: {event_id}")
        print(f"  Source: {step['source']}")
        print(f"  Type: {step['event_type']}")
        print()

        time.sleep(0.5)

    print("=" * 60)
    print("INCIDENT CREATED")
    print("=" * 60)
    print()
    print(f"Incident: Coordinated Quishing + IoT Beaconing + API Abuse")
    print(f"Incident ID: {incident_id}")
    print(f"Risk Score: 91 / 100")
    print()
    print("Evidence:")
    print("- QR phishing simulation triggered")
    print("- DNS query to suspicious domain")
    print("- Device ZK attestation expired")
    print("- CTI match confidence: 82%")
    print("- API abuse from related ASN")
    print("- Asset belongs to finance network segment")
    print()
    print("Recommended Actions:")
    print("- Block suspicious domain")
    print("- Quarantine IoT device")
    print("- Rotate affected credentials")
    print("- Enable WAF rate limit")
    print("- Open SOC L2 case")

if __name__ == "__main__":
    run_demo_attack()
