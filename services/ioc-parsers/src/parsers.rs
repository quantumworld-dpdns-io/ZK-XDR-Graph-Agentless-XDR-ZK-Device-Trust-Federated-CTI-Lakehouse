use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub ioc_type: String,
    pub value: String,
    pub confidence: u8,
    pub context: Option<String>,
}

pub static IP_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<ip>\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b)").unwrap()
});

pub static DOMAIN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<domain>\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)").unwrap()
});

pub static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?P<url>https?://[^\s<>\"']+)"#).unwrap()
});

pub static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<email>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)").unwrap()
});

pub static MD5_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<md5>[a-fA-F0-9]{32})\b").unwrap()
});

pub static SHA256_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<sha256>[a-fA-F0-9]{64})\b").unwrap()
});

pub static CVE_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?P<cve>CVE-\d{4}-\d{4,})\b").unwrap()
});

pub fn extract_iocs(text: &str) -> Vec<IoC> {
    let mut iocs = Vec::new();

    // Extract IPs
    for cap in IP_REGEX.captures_iter(text) {
        let ip = cap["ip"].to_string();
        if !is_private_ip(&ip) {
            iocs.push(IoC {
                ioc_type: "ip_address".to_string(),
                value: ip,
                confidence: 80,
                context: Some("extracted_from_text".to_string()),
            });
        }
    }

    // Extract domains
    for cap in DOMAIN_REGEX.captures_iter(text) {
        let domain = cap["domain"].to_string();
        iocs.push(IoC {
            ioc_type: "domain".to_string(),
            value: domain,
            confidence: 70,
            context: Some("extracted_from_text".to_string()),
        });
    }

    // Extract URLs
    for cap in URL_REGEX.captures_iter(text) {
        let url = cap["url"].to_string();
        iocs.push(IoC {
            ioc_type: "url".to_string(),
            value: url,
            confidence: 90,
            context: Some("extracted_from_text".to_string()),
        });
    }

    // Extract emails
    for cap in EMAIL_REGEX.captures_iter(text) {
        let email = cap["email"].to_string();
        iocs.push(IoC {
            ioc_type: "email_address".to_string(),
            value: email,
            confidence: 75,
            context: Some("extracted_from_text".to_string()),
        });
    }

    // Extract MD5 hashes
    for cap in MD5_REGEX.captures_iter(text) {
        let md5 = cap["md5"].to_string();
        iocs.push(IoC {
            ioc_type: "file_hash_md5".to_string(),
            value: md5,
            confidence: 85,
            context: Some("extracted_from_text".to_string()),
        });
    }

    // Extract SHA256 hashes
    for cap in SHA256_REGEX.captures_iter(text) {
        let sha256 = cap["sha256"].to_string();
        iocs.push(IoC {
            ioc_type: "file_hash_sha256".to_string(),
            value: sha256,
            confidence: 95,
            context: Some("extracted_from_text".to_string()),
        });
    }

    // Extract CVEs
    for cap in CVE_REGEX.captures_iter(text) {
        let cve = cap["cve"].to_string();
        iocs.push(IoC {
            ioc_type: "cve".to_string(),
            value: cve,
            confidence: 100,
            context: Some("extracted_from_text".to_string()),
        });
    }

    iocs
}

fn is_private_ip(ip: &str) -> bool {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 {
        return false;
    }
    parts[0] == 10
        || (parts[0] == 172 && parts[1] >= 16 && parts[1] <= 31)
        || (parts[0] == 192 && parts[1] == 168)
        || parts[0] == 127
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ips() {
        let text = "Connection from 203.0.113.42 to 198.51.100.23";
        let iocs = extract_iocs(text);
        assert!(iocs.iter().any(|i| i.ioc_type == "ip_address" && i.value == "203.0.113.42"));
    }

    #[test]
    fn test_extract_domains() {
        let text = "Requested domain: evil-domain.xyz";
        let iocs = extract_iocs(text);
        assert!(iocs.iter().any(|i| i.ioc_type == "domain" && i.value == "evil-domain.xyz"));
    }

    #[test]
    fn test_extract_cves() {
        let text = "Vulnerability CVE-2024-12345 exploited";
        let iocs = extract_iocs(text);
        assert!(iocs.iter().any(|i| i.ioc_type == "cve" && i.value == "CVE-2024-12345"));
    }

    #[test]
    fn test_private_ip_excluded() {
        let text = "Internal: 192.168.1.1 and external: 8.8.8.8";
        let iocs = extract_iocs(text);
        assert!(!iocs.iter().any(|i| i.value == "192.168.1.1"));
        assert!(iocs.iter().any(|i| i.value == "8.8.8.8"));
    }

    #[test]
    fn test_extract_sha256() {
        let text = "Hash: abc123def456abc123def456abc123def456abc123def456abc123def456abc1";
        let iocs = extract_iocs(text);
        assert!(iocs.iter().any(|i| i.ioc_type == "file_hash_sha256"));
    }
}
