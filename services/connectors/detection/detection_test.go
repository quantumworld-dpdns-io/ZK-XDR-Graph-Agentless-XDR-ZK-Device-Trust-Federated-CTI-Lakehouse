package detection

import (
	"testing"
)

func TestIsSuspiciousDomain(t *testing.T) {
	tests := []struct {
		domain      string
		suspicious  bool
	}{
		{"malicious-site.xyz", true},
		{"phishing.top", true},
		{"bad-domain.tk", true},
		{"normal-domain.com", false},
		{"company.org", false},
		{"internal.dev", false},
	}
	for _, tt := range tests {
		result := IsSuspiciousDomain(tt.domain)
		if result != tt.suspicious {
			t.Errorf("IsSuspiciousDomain(%s): expected %v, got %v", tt.domain, tt.suspicious, result)
		}
	}
}

func TestIsDGAPattern(t *testing.T) {
	tests := []struct {
		domain   string
		isDGA    bool
	}{
		{"xkrjfmalwpqtop.com", true},
		{"qwertyuiopasdfg.xyz", true},
		{"normal-website.com", false},
		{"short.xyz", false},
		{"a.b", false},
		{"github.com", false},
	}
	for _, tt := range tests {
		result := IsDGAPattern(tt.domain)
		if result != tt.isDGA {
			t.Errorf("IsDGAPattern(%s): expected %v, got %v", tt.domain, tt.isDGA, result)
		}
	}
}

func TestContainsSuspiciousAttachment(t *testing.T) {
	tests := []struct {
		attachTypes []string
		suspicious  bool
	}{
		{[]string{".exe"}, true},
		{[]string{".zip", ".docm"}, true},
		{[]string{".pdf", ".docx"}, false},
		{[]string{".ps1", ".vbs"}, true},
		{[]string{".jpg", ".png"}, false},
	}
	for _, tt := range tests {
		result := ContainsSuspiciousAttachment(tt.attachTypes)
		if result != tt.suspicious {
			t.Errorf("ContainsSuspiciousAttachment(%v): expected %v, got %v", tt.attachTypes, tt.suspicious, result)
		}
	}
}

func TestClassifyWAFEvent(t *testing.T) {
	tests := []struct {
		statusCode int
		ruleAction string
		expected   string
	}{
		{200, "allow", "waf.request.normal"},
		{429, "", "waf.rate_limit.exceeded"},
		{200, "block", "waf.rule.blocked"},
		{500, "", "waf.server.error"},
		{403, "", "waf.access.denied"},
		{401, "", "waf.auth.failure"},
	}
	for _, tt := range tests {
		result := ClassifyWAFEvent(tt.statusCode, tt.ruleAction)
		if result != tt.expected {
			t.Errorf("ClassifyWAFEvent(%d, %s): expected %s, got %s", tt.statusCode, tt.ruleAction, tt.expected, result)
		}
	}
}

func TestClassifyMailEvent(t *testing.T) {
	tests := []struct {
		phishScore float64
		spamScore  float64
		spfPass    bool
		dkimPass   bool
		expected   string
	}{
		{0.9, 0.5, false, false, "email.phishing.detected"},
		{0.3, 0.5, false, false, "email.auth.failure"},
		{0.5, 0.5, true, true, "email.possibly_phishing"},
		{0.1, 0.2, true, true, "email.received.normal"},
		{0.2, 0.9, true, true, "email.phishing.detected"},
	}
	for _, tt := range tests {
		result := ClassifyMailEvent(tt.phishScore, tt.spamScore, tt.spfPass, tt.dkimPass)
		if result != tt.expected {
			t.Errorf("ClassifyMailEvent(%.1f, %.1f, %v, %v): expected %s, got %s",
				tt.phishScore, tt.spamScore, tt.spfPass, tt.dkimPass, tt.expected, result)
		}
	}
}
