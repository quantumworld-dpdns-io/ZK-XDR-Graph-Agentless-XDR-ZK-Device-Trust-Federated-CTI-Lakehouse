package scoring

import (
	"testing"
	"time"
)

func TestComputeTrustScore_CleanAsset(t *testing.T) {
	factors := AssetRiskFactors{
		ZKAttestation:  0,
		EventFrequency: 5,
		SeverityWeight: 0,
		CTIMatchCount:  0,
		VulnExposure:   0,
		Criticality:    "medium",
		LastEventAge:   0,
	}
	score := ComputeTrustScore(factors)
	if score < 70 || score > 80 {
		t.Errorf("Clean asset trust score should be ~75, got %d", score)
	}
}

func TestComputeTrustScore_HighRisk(t *testing.T) {
	factors := AssetRiskFactors{
		ZKAttestation:  0,
		EventFrequency: 50,
		SeverityWeight: 1.0,
		CTIMatchCount:  5,
		VulnExposure:   3,
		Criticality:    "critical",
		LastEventAge:   0,
	}
	score := ComputeTrustScore(factors)
	if score > 40 {
		t.Errorf("High risk asset should have low trust score, got %d", score)
	}
}

func TestComputeTrustScore_ZKAttestation(t *testing.T) {
	noZK := AssetRiskFactors{ZKAttestation: 0, EventFrequency: 5, Criticality: "medium"}
	withZK := AssetRiskFactors{ZKAttestation: 10, EventFrequency: 5, Criticality: "medium"}

	scoreNoZK := ComputeTrustScore(noZK)
	scoreWithZK := ComputeTrustScore(withZK)

	if scoreWithZK >= scoreNoZK {
		t.Errorf("ZK attestation should increase trust score: noZK=%d, withZK=%d", scoreNoZK, scoreWithZK)
	}
}

func TestComputeTrustScore_Clamping(t *testing.T) {
	minimal := AssetRiskFactors{Criticality: "low"}
	score := ComputeTrustScore(minimal)
	if score < 0 || score > 100 {
		t.Errorf("Score should be clamped to 0-100, got %d", score)
	}

	maximal := AssetRiskFactors{
		ZKAttestation:  100,
		EventFrequency: 0,
		SeverityWeight: 0,
		CTIMatchCount:  0,
		VulnExposure:   0,
		Criticality:    "critical",
		LastEventAge:   0,
	}
	score = ComputeTrustScore(maximal)
	if score < 0 || score > 100 {
		t.Errorf("Score should be clamped to 0-100, got %d", score)
	}
}

func TestDetermineStatus(t *testing.T) {
	tests := []struct {
		score  int
		status string
	}{
		{90, "trusted"},
		{75, "active"},
		{50, "suspicious"},
		{30, "quarantined"},
		{0, "quarantined"},
		{100, "trusted"},
	}
	for _, tt := range tests {
		status := DetermineStatus(tt.score)
		if status != tt.status {
			t.Errorf("Score %d: expected %s, got %s", tt.score, tt.status, status)
		}
	}
}

func TestComputeIncidentRiskScore(t *testing.T) {
	score := ComputeIncidentRiskScore("critical", 10, 5)
	if score < 800 || score > 1000 {
		t.Errorf("Critical incident risk score should be 800-1000, got %d", score)
	}

	score = ComputeIncidentRiskScore("low", 1, 1)
	if score != 200 {
		t.Errorf("Low incident risk score should be 200, got %d", score)
	}

	score = ComputeIncidentRiskScore("critical", 50, 5)
	if score != 1000 {
		t.Errorf("High excess should be clamped to 1000, got %d", score)
	}
}

func TestTimeSinceLastEvent(t *testing.T) {
	hours := TimeSinceLastEvent(time.Now().Add(-24 * time.Hour))
	if hours < 23 || hours > 25 {
		t.Errorf("Expected ~24 hours, got %d", hours)
	}
}
