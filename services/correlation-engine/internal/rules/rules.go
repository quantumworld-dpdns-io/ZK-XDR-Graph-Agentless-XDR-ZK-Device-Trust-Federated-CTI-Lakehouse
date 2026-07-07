package rules

import "time"

type CorrelationRule struct {
	Name           string
	EventType      string
	TimeWindow     time.Duration
	MinEventCount  int
	Severity       string
	IncidentType   string
	MitreTactic    string
	MitreTechnique string
}

var CorrelationRules = []CorrelationRule{
	{
		Name:           "Credential Stuffing",
		EventType:      "waf.auth.failure",
		TimeWindow:     10 * time.Minute,
		MinEventCount:  5,
		Severity:       "high",
		IncidentType:   "api_abuse",
		MitreTactic:    "credential-access",
		MitreTechnique: "T1110",
	},
	{
		Name:           "DDoS Attack",
		EventType:      "waf.rate_limit.exceeded",
		TimeWindow:     5 * time.Minute,
		MinEventCount:  10,
		Severity:       "critical",
		IncidentType:   "ddos",
		MitreTactic:    "impact",
		MitreTechnique: "T1499",
	},
	{
		Name:           "Phishing Campaign",
		EventType:      "email.phishing.detected",
		TimeWindow:     30 * time.Minute,
		MinEventCount:  3,
		Severity:       "high",
		IncidentType:   "quishing_bec",
		MitreTactic:    "initial-access",
		MitreTechnique: "T1566",
	},
	{
		Name:           "DGA Domain Activity",
		EventType:      "dns.query.dga",
		TimeWindow:     15 * time.Minute,
		MinEventCount:  3,
		Severity:       "critical",
		IncidentType:   "c2_communication",
		MitreTactic:    "command-and-control",
		MitreTechnique: "T1568.002",
	},
	{
		Name:           "Suspicious DNS Beaconing",
		EventType:      "dns.query.suspicious",
		TimeWindow:     20 * time.Minute,
		MinEventCount:  5,
		Severity:       "high",
		IncidentType:   "suspicious_iot_beaconing",
		MitreTactic:    "command-and-control",
		MitreTechnique: "T1071.004",
	},
}

func MatchRule(eventType string) []CorrelationRule {
	var matched []CorrelationRule
	for _, rule := range CorrelationRules {
		if rule.EventType == eventType {
			matched = append(matched, rule)
		}
	}
	return matched
}

func ShouldTrigger(rule CorrelationRule, count int) bool {
	return count >= rule.MinEventCount
}

func ComputeRiskScore(severity string, count, minCount int) int {
	baseScore := 0
	switch severity {
	case "critical":
		baseScore = 800
	case "high":
		baseScore = 650
	case "medium":
		baseScore = 400
	case "low":
		baseScore = 200
	}

	excess := count - minCount
	if excess > 0 {
		baseScore += excess * 10
	}

	if baseScore > 1000 {
		baseScore = 1000
	}
	return baseScore
}
