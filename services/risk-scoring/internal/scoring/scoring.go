package scoring

import "time"

type AssetRiskFactors struct {
	ZKAttestation  int     `json:"zk_attestation"`
	EventFrequency int     `json:"event_frequency"`
	SeverityWeight float64 `json:"severity_weight"`
	CTIMatchCount  int     `json:"cti_match_count"`
	VulnExposure   int     `json:"vuln_exposure"`
	NetworkSegment string  `json:"network_segment"`
	Criticality    string  `json:"criticality"`
	LastEventAge   int     `json:"last_event_age_hours"`
}

var SeverityWeights = map[string]float64{
	"info":     0.0,
	"low":      0.25,
	"medium":   0.50,
	"high":     0.75,
	"critical": 1.0,
}

var CriticalityModifiers = map[string]float64{
	"critical": -20,
	"high":     -10,
	"medium":   0,
	"low":      10,
}

func ComputeTrustScore(factors AssetRiskFactors) int {
	score := 80.0

	score -= float64(factors.ZKAttestation) * 0.2

	if factors.EventFrequency > 10 {
		score -= float64(factors.EventFrequency-10) * 1.5
	}

	score -= factors.SeverityWeight * 30
	score -= float64(factors.CTIMatchCount) * 5
	score -= float64(factors.VulnExposure) * 3

	if mod, ok := CriticalityModifiers[factors.Criticality]; ok {
		score += mod
	}

	if factors.LastEventAge > 72 {
		score -= 5
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return int(score)
}

func DetermineStatus(trustScore int) string {
	switch {
	case trustScore < 40:
		return "quarantined"
	case trustScore < 60:
		return "suspicious"
	case trustScore < 80:
		return "active"
	default:
		return "trusted"
	}
}

func ComputeIncidentRiskScore(severity string, count, minCount int) int {
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

func TimeSinceLastEvent(lastEvent time.Time) int {
	return int(time.Since(lastEvent).Hours())
}
