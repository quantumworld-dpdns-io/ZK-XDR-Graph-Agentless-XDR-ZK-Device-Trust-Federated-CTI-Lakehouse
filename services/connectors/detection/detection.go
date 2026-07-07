package detection

import "strings"

var SuspiciousTLDs = map[string]bool{
	".xyz": true, ".top": true, ".buzz": true, ".tk": true,
	".ml": true, ".ga": true, ".cf": true, ".gq": true,
}

func IsSuspiciousDomain(domain string) bool {
	for tld := range SuspiciousTLDs {
		if len(domain) > len(tld) && domain[len(domain)-len(tld):] == tld {
			return true
		}
	}
	return false
}

func IsDGAPattern(domain string) bool {
	if len(domain) < 8 {
		return false
	}
	consonantCount := 0
	totalChars := 0
	lower := strings.ToLower(domain)
	for _, c := range lower {
		if c == '.' {
			continue
		}
		totalChars++
		switch c {
		case 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z':
			consonantCount++
		}
	}
	if totalChars == 0 {
		return false
	}
	ratio := float64(consonantCount) / float64(totalChars)
	return ratio > 0.70 && totalChars > 10
}

func ContainsSuspiciousAttachment(types []string) bool {
	suspicious := map[string]bool{
		".exe": true, ".scr": true, ".bat": true, ".cmd": true,
		".js": true, ".vbs": true, ".ps1": true, ".docm": true,
		".xlsm": true, ".pptm": true, ".zip": true, ".rar": true,
	}
	for _, t := range types {
		if suspicious[t] {
			return true
		}
	}
	return false
}

func ClassifyWAFEvent(statusCode int, ruleAction string) string {
	switch {
	case ruleAction == "block":
		return "waf.rule.blocked"
	case statusCode == 429:
		return "waf.rate_limit.exceeded"
	case statusCode >= 500:
		return "waf.server.error"
	case statusCode == 403:
		return "waf.access.denied"
	case statusCode == 401:
		return "waf.auth.failure"
	default:
		return "waf.request.normal"
	}
}

func ClassifyMailEvent(phishScore, spamScore float64, spfPass, dkimPass bool) string {
	if phishScore > 0.7 || spamScore > 0.8 {
		return "email.phishing.detected"
	}
	if !spfPass || !dkimPass {
		return "email.auth.failure"
	}
	if phishScore > 0.4 {
		return "email.possibly_phishing"
	}
	return "email.received.normal"
}
