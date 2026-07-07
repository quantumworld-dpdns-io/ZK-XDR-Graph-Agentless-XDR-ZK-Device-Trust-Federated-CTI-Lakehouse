"""Analyst Copilot - RAG-powered threat analysis and recommendations."""

import os
from typing import Any

import structlog

logger = structlog.get_logger()

# Knowledge base for threat patterns
THREAT_KNOWLEDGE = {
    "dns.query.suspicious": {
        "description": "Suspicious DNS query detected, possibly indicating C2 communication or data exfiltration",
        "severity": "high",
        "mitre_tactics": ["command-and-control", "exfiltration"],
        "mitre_techniques": ["T1071.004", "T1048"],
        "investigation_steps": [
            "Check if the domain is known malicious (CTI lookup)",
            "Analyze DNS query frequency and patterns",
            "Correlate with network flow data",
            "Check for associated IP addresses",
            "Review asset trust score and recent events",
        ],
        "response_actions": [
            "Block domain at DNS level",
            "Quarantine affected device",
            "Notify SOC team",
            "Create incident for tracking",
        ],
    },
    "dns.query.dga": {
        "description": "DGA (Domain Generation Algorithm) domain detected, indicating malware C2 activity",
        "severity": "critical",
        "mitre_tactics": ["command-and-control"],
        "mitre_techniques": ["T1568.002"],
        "investigation_steps": [
            "Isolate the affected device immediately",
            "Capture network traffic for analysis",
            "Check for other DGA domains from same source",
            "Analyze process on the device",
            "Look for lateral movement indicators",
        ],
        "response_actions": [
            "Quarantine device",
            "Block all DGA domains",
            "Trigger forensic snapshot",
            "Escalate to incident response team",
        ],
    },
    "email.phishing.detected": {
        "description": "Phishing email detected, potentially targeting credentials or delivering malware",
        "severity": "high",
        "mitre_tactics": ["initial-access"],
        "mitre_techniques": ["T1566", "T1566.001"],
        "investigation_steps": [
            "Check if email was opened or links clicked",
            "Verify attachment hashes against malware DB",
            "Check for similar emails to other users",
            "Analyze sender reputation",
            "Review email headers for spoofing indicators",
        ],
        "response_actions": [
            "Quarantine email from all mailboxes",
            "Block sender domain/IP",
            "Notify affected users",
            "Reset credentials if credentials entered",
        ],
    },
    "waf.auth.failure": {
        "description": "Multiple authentication failures detected, possible credential stuffing or brute force",
        "severity": "high",
        "mitre_tactics": ["credential-access"],
        "mitre_techniques": ["T1110"],
        "investigation_steps": [
            "Identify source IPs and their reputation",
            "Check for successful logins from same source",
            "Analyze target accounts",
            "Review rate limiting effectiveness",
            "Check for password spray patterns",
        ],
        "response_actions": [
            "Block source IPs",
            "Enable account lockout policies",
            "Force password resets for targeted accounts",
            "Notify security team",
        ],
    },
    "waf.rate_limit.exceeded": {
        "description": "Rate limit exceeded, indicating potential DDoS or API abuse",
        "severity": "medium",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1499"],
        "investigation_steps": [
            "Identify attack pattern and sources",
            "Check if legitimate traffic spike",
            "Analyze request patterns",
            "Review geo-distribution of requests",
        ],
        "response_actions": [
            "Enable aggressive rate limiting",
            "Geo-block high-risk regions",
            "Notify NOC team",
        ],
    },
    "zk.device.attestation.failed": {
        "description": "ZK device attestation failed, indicating device identity compromise or tampering",
        "severity": "critical",
        "mitre_tactics": ["defense-evasion", "persistence"],
        "mitre_techniques": ["T1542", "T1542.001"],
        "investigation_steps": [
            "Check device trust score history",
            "Verify hardware attestation chain",
            "Compare against known good state",
            "Check for recent firmware updates",
            "Review device network activity",
        ],
        "response_actions": [
            "Quarantine device immediately",
            "Revoke device certificates",
            "Force re-attestation",
            "Notify device management team",
        ],
    },
}


class AnalystCopilotService:
    """RAG-powered analyst copilot for threat investigation."""

    def __init__(self):
        self.knowledge = THREAT_KNOWLEDGE

    async def query(self, question: str, context: str | None = None) -> dict[str, Any]:
        """Answer analyst questions about threats and incidents."""
        # Find relevant knowledge
        relevant_knowledge = []
        for event_type, info in self.knowledge.items():
            if event_type.lower() in question.lower() or any(
                word in question.lower()
                for word in event_type.split(".")
            ):
                relevant_knowledge.append({"event_type": event_type, **info})

        if not relevant_knowledge:
            # Generic response
            return {
                "answer": f"I can help you investigate '{question}'. Based on the available data, I recommend checking the asset risk graph for related events and correlating with CTI indicators.",
                "sources": [],
                "confidence": 0.5,
                "suggested_actions": [
                    "Review timeline for related events",
                    "Check CTI indicators",
                    "Analyze asset trust score",
                ],
            }

        # Build answer from knowledge
        best_match = relevant_knowledge[0]
        answer = f"**{best_match.get('description', 'Threat detected')}**\n\n"
        answer += f"Severity: **{best_match.get('severity', 'unknown')}**\n"
        answer += f"MITRE Tactics: {', '.join(best_match.get('mitre_tactics', []))}\n"
        answer += f"MITRE Techniques: {', '.join(best_match.get('mitre_techniques', []))}\n\n"

        answer += "**Investigation Steps:**\n"
        for i, step in enumerate(best_match.get("investigation_steps", []), 1):
            answer += f"{i}. {step}\n"

        answer += "\n**Recommended Response:**\n"
        for action in best_match.get("response_actions", []):
            answer += f"- {action}\n"

        return {
            "answer": answer,
            "sources": [{"event_type": k["event_type"], "confidence": 0.9} for k in relevant_knowledge[:3]],
            "confidence": 0.85,
            "suggested_actions": best_match.get("response_actions", []),
        }

    async def enrich_indicator(self, indicator_type: str, value: str) -> dict[str, Any]:
        """Enrich a threat indicator with context."""
        # Simulate enrichment lookup
        enrichment = {
            "indicator": value,
            "threat_type": "unknown",
            "severity": "medium",
            "confidence": 50,
            "description": f"Indicator {value} ({indicator_type}) requires further analysis",
            "mitre_tactics": [],
            "mitre_techniques": [],
            "related_iocs": [],
            "recommended_actions": [
                "Submit to sandbox for analysis",
                "Check CTI feeds for matches",
                "Monitor for related activity",
            ],
        }

        # Check if indicator matches known patterns
        if indicator_type == "domain":
            if any(tld in value for tld in [".xyz", ".top", ".buzz"]):
                enrichment["threat_type"] = "suspicious_domain"
                enrichment["severity"] = "high"
                enrichment["confidence"] = 75
                enrichment["description"] = f"Domain {value} uses suspicious TLD"
                enrichment["mitre_tactics"] = ["command-and-control"]
                enrichment["mitre_techniques"] = ["T1071.004"]
        elif indicator_type == "ip_address":
            enrichment["threat_type"] = "network_indicator"
            enrichment["description"] = f"IP {value} requires reputation check"

        return enrichment

    async def summarize_incident(self, incident_id: str, events: list[dict]) -> dict[str, Any]:
        """Generate an incident summary."""
        severity_counts = {}
        sources = set()
        assets = set()

        for event in events:
            sev = event.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            sources.add(event.get("source", "unknown"))
            if event.get("asset_id"):
                assets.add(event["asset_name"] or event["asset_id"])

        max_severity = "info"
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                max_severity = sev
                break

        return {
            "incident_id": incident_id,
            "summary": f"Incident {incident_id} involves {len(events)} correlated events from {', '.join(sources)}. "
                       f"Highest severity: {max_severity}. "
                       f"Affected assets: {', '.join(assets) if assets else 'unknown'}.",
            "severity_assessment": max_severity,
            "root_cause": "Correlated events suggest coordinated attack pattern",
            "affected_assets": list(assets),
            "recommended_response": [
                f"Investigate {len(events)} related events",
                "Review asset trust scores",
                "Check CTI indicators",
                "Consider device quarantine if trust score low",
            ],
            "similar_incidents": [],
        }


copilot_service = AnalystCopilotService()
