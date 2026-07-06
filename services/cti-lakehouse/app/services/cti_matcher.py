"""CTI IoC Matching Service - Consumes XDR events and matches against IoCs."""

import json
import os
import signal
import sys
import time
from typing import Any

import redis
import structlog

logger = structlog.get_logger()

# In-memory IoC store for matching (in production, use ClickHouse or Qdrant)
IOC_STORE: dict[str, dict[str, Any]] = {}


def load_sample_iocs():
    """Load sample IoCs for development."""
    global IOC_STORE
    IOC_STORE = {
        "203.0.113.42": {
            "type": "ip_address",
            "value": "203.0.113.42",
            "severity": "high",
            "confidence": 90,
            "tlp": "red",
            "source": "internal_siem",
            "tags": ["c2", "apt28"],
            "mitre_tactics": ["command-and-control"],
            "mitre_techniques": ["T1071"],
        },
        "strange-domain.example": {
            "type": "domain",
            "value": "strange-domain.example",
            "severity": "high",
            "confidence": 82,
            "tlp": "amber",
            "source": "federated_sme_cluster",
            "tags": ["phishing", "c2"],
            "mitre_tactics": ["command-and-control", "initial-access"],
            "mitre_techniques": ["T1566", "T1071.004"],
        },
        "abc123def456": {
            "type": "file_hash_sha256",
            "value": "abc123def456",
            "severity": "critical",
            "confidence": 95,
            "tlp": "red",
            "source": "virustotal",
            "tags": ["malware", "ransomware"],
            "mitre_tactics": ["execution", "persistence"],
            "mitre_techniques": ["T1204", "T1547"],
        },
    }
    logger.info("Loaded sample IoCs", count=len(IOC_STORE))


def match_event_against_iocs(event_data: dict) -> list[dict]:
    """Match an XDR event against known IoCs."""
    matches = []

    # Extract values to match from event
    values_to_check = []
    if event_data.get("source_ip"):
        values_to_check.append(("ip_address", event_data["source_ip"]))
    if event_data.get("dest_ip"):
        values_to_check.append(("ip_address", event_data["dest_ip"]))
    if event_data.get("domain"):
        values_to_check.append(("domain", event_data["domain"]))
    if event_data.get("file_hash"):
        values_to_check.append(("file_hash_sha256", event_data["file_hash"]))
    if event_data.get("url"):
        values_to_check.append(("url", event_data["url"]))

    for ioc_type, value in values_to_check:
        if value in IOC_STORE:
            ioc = IOC_STORE[value]
            if ioc["type"] == ioc_type:
                match = {
                    "event_id": event_data.get("event_id", "unknown"),
                    "ioc_type": ioc_type,
                    "ioc_value": value,
                    "severity": ioc["severity"],
                    "confidence": ioc["confidence"],
                    "tlp": ioc["tlp"],
                    "source": ioc["source"],
                    "matched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }
                matches.append(match)
                logger.info(
                    "IoC match found",
                    event_id=event_data.get("event_id"),
                    ioc_type=ioc_type,
                    ioc_value=value,
                )

    return matches


def process_event(rdb: redis.Redis, event_data: dict) -> None:
    """Process a single XDR event and check for IoC matches."""
    matches = match_event_against_iocs(event_data)

    for match in matches:
        # Publish match to Redis Stream for downstream consumers
        rdb.xadd(
            "xdr:cti_matches",
            {"data": json.dumps(match)},
        )
        logger.info("Published CTI match", match=match)


def main():
    """Main event loop for CTI matching service."""
    redis_addr = os.getenv("REDIS_ADDR", "localhost:6379")
    redis_password = os.getenv("REDIS_PASSWORD", "")

    rdb = redis.Redis(
        host=redis_addr.split(":")[0],
        port=int(redis_addr.split(":")[1]) if ":" in redis_addr else 6379,
        password=redis_password or None,
        decode_responses=True,
    )

    try:
        rdb.ping()
        logger.info("Connected to Redis", addr=redis_addr)
    except redis.ConnectionError:
        logger.error("Failed to connect to Redis", addr=redis_addr)
        sys.exit(1)

    load_sample_iocs()

    # Ensure consumer group
    try:
        rdb.xgroup_create("xdr:events", "cti-matchers", "0", mkstream=True)
    except redis.ResponseError:
        pass  # Group already exists

    logger.info("CTI matching service started")

    running = True

    def shutdown(signum, frame):
        nonlocal running
        logger.info("Shutting down CTI matching service")
        running = False

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while running:
        try:
            streams = rdb.xreadgroup(
                "cti-matchers",
                "cti-matcher-1",
                {"xdr:events": ">"},
                count=50,
                block=5000,
            )

            for stream_name, messages in streams:
                for msg_id, fields in messages:
                    data = fields.get("data", "{}")
                    try:
                        event_data = json.loads(data)
                        process_event(rdb, event_data)
                    except json.JSONDecodeError:
                        logger.error("Failed to parse event data", raw=data)

                    rdb.xack("xdr:events", "cti-matchers", msg_id)

        except redis.ConnectionError:
            logger.error("Redis connection lost, retrying in 5s...")
            time.sleep(5)
        except Exception as e:
            logger.error("Error processing events", error=str(e))
            time.sleep(1)


if __name__ == "__main__":
    main()
