package rules

import (
	"testing"
)

func TestMatchRule(t *testing.T) {
	tests := []struct {
		eventType   string
		shouldMatch bool
	}{
		{"waf.auth.failure", true},
		{"waf.rate_limit.exceeded", true},
		{"email.phishing.detected", true},
		{"dns.query.dga", true},
		{"dns.query.suspicious", true},
		{"dns.query.normal", false},
		{"waf.request.normal", false},
	}
	for _, tt := range tests {
		matched := MatchRule(tt.eventType)
		if (len(matched) > 0) != tt.shouldMatch {
			t.Errorf("MatchRule(%s): expected match=%v, got %d rules", tt.eventType, tt.shouldMatch, len(matched))
		}
	}
}

func TestShouldTrigger(t *testing.T) {
	rule := CorrelationRule{MinEventCount: 5}

	if ShouldTrigger(rule, 4) {
		t.Error("Should not trigger with count < minCount")
	}
	if !ShouldTrigger(rule, 5) {
		t.Error("Should trigger with count == minCount")
	}
	if !ShouldTrigger(rule, 10) {
		t.Error("Should trigger with count > minCount")
	}
}

func TestComputeRiskScore(t *testing.T) {
	tests := []struct {
		severity string
		count    int
		minCount int
		expected int
	}{
		{"critical", 10, 5, 850},
		{"high", 10, 5, 700},
		{"medium", 10, 5, 450},
		{"low", 10, 5, 250},
		{"critical", 50, 5, 1000},
		{"critical", 5, 5, 800},
	}
	for _, tt := range tests {
		result := ComputeRiskScore(tt.severity, tt.count, tt.minCount)
		if result != tt.expected {
			t.Errorf("ComputeRiskScore(%s, %d, %d): expected %d, got %d",
				tt.severity, tt.count, tt.minCount, tt.expected, result)
		}
	}
}

func TestCorrelationRulesIntegrity(t *testing.T) {
	if len(CorrelationRules) != 5 {
		t.Errorf("Expected 5 correlation rules, got %d", len(CorrelationRules))
	}

	for _, rule := range CorrelationRules {
		if rule.Name == "" {
			t.Error("Rule has empty name")
		}
		if rule.EventType == "" {
			t.Errorf("Rule %s has empty event type", rule.Name)
		}
		if rule.Severity == "" {
			t.Errorf("Rule %s has empty severity", rule.Name)
		}
		if rule.MitreTechnique == "" {
			t.Errorf("Rule %s has empty MITRE technique", rule.Name)
		}
	}
}
