package normalizer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/event-normalizer/internal/models"
)

type Normalizer interface {
	Normalize(raw map[string]interface{}) (*models.XDREvent, error)
}

type NormalizerFactory struct {
	normalizers map[string]Normalizer
}

func NewNormalizerFactory() *NormalizerFactory {
	f := &NormalizerFactory{
		normalizers: make(map[string]Normalizer),
	}

	f.normalizers["ddi"] = &DDINormalizer{}
	f.normalizers["waf"] = &WAFNormalizer{}
	f.normalizers["mail"] = &MailNormalizer{}
	f.normalizers["zk"] = &ZKNormalizer{}
	f.normalizers["endpoint"] = &EndpointNormalizer{}

	return f
}

func (f *NormalizerFactory) Get(source string) (Normalizer, bool) {
	n, ok := f.normalizers[source]
	return n, ok
}

func (f *NormalizerFactory) Normalize(source string, raw map[string]interface{}) (*models.XDREvent, error) {
	n, ok := f.normalizers[source]
	if !ok {
		return nil, fmt.Errorf("unknown source: %s", source)
	}
	return n.Normalize(raw)
}

type DDINormalizer struct{}

func (n *DDINormalizer) Normalize(raw map[string]interface{}) (*models.XDREvent, error) {
	event := &models.XDREvent{
		EventID:    "evt_" + uuid.New().String()[:12],
		Source:     "ddi",
		EventType:  "dns.query.suspicious",
		Severity:   "medium",
		ObservedAt: time.Now().UTC(),
		Raw:        raw,
		Normalized: make(map[string]interface{}),
		Trace: &models.TraceInfo{
			Collector:     "ddi-connector",
			Pipeline:      "redis-streams:xdr.events",
			SchemaVersion: "xdr-event-v0.1",
		},
		MITRE: &models.MITREInfo{
			Tactics:    []string{"discovery", "command-and-control"},
			Techniques: []string{"T1071.004", "T1568.002"},
		},
	}

	if query, ok := raw["query"].(string); ok {
		event.Normalized["domain"] = query
	}
	if srcIP, ok := raw["src_ip"].(string); ok {
		event.Normalized["src_ip"] = srcIP
	}
	if deviceID, ok := raw["device_id"].(string); ok {
		event.DeviceID = deviceID
	}

	event.Risk = &models.RiskScore{
		Score:   50,
		Factors: []string{"new_domain", "dns_query"},
	}

	return event, nil
}

type WAFNormalizer struct{}

func (n *WAFNormalizer) Normalize(raw map[string]interface{}) (*models.XDREvent, error) {
	event := &models.XDREvent{
		EventID:    "evt_" + uuid.New().String()[:12],
		Source:     "waf",
		EventType:  "waf.anomaly.detected",
		Severity:   "high",
		ObservedAt: time.Now().UTC(),
		Raw:        raw,
		Normalized: make(map[string]interface{}),
		Trace: &models.TraceInfo{
			Collector:     "waf-api-connector",
			Pipeline:      "redis-streams:xdr.events",
			SchemaVersion: "xdr-event-v0.1",
		},
		MITRE: &models.MITREInfo{
			Tactics:    []string{"initial-access", "credential-access"},
			Techniques: []string{"T1190", "T1110"},
		},
	}

	if path, ok := raw["path"].(string); ok {
		event.Normalized["request_path"] = path
	}
	if method, ok := raw["method"].(string); ok {
		event.Normalized["http_method"] = method
	}
	if srcIP, ok := raw["src_ip"].(string); ok {
		event.Normalized["src_ip"] = srcIP
	}

	event.Risk = &models.RiskScore{
		Score:   70,
		Factors: []string{"waf_anomaly", "rate_spike"},
	}

	return event, nil
}

type MailNormalizer struct{}

func (n *MailNormalizer) Normalize(raw map[string]interface{}) (*models.XDREvent, error) {
	event := &models.XDREvent{
		EventID:    "evt_" + uuid.New().String()[:12],
		Source:     "mail",
		EventType:  "email.phishing.detected",
		Severity:   "high",
		ObservedAt: time.Now().UTC(),
		Raw:        raw,
		Normalized: make(map[string]interface{}),
		Trace: &models.TraceInfo{
			Collector:     "mail-threat-connector",
			Pipeline:      "redis-streams:xdr.events",
			SchemaVersion: "xdr-event-v0.1",
		},
		MITRE: &models.MITREInfo{
			Tactics:    []string{"initial-access"},
			Techniques: []string{"T1566.001", "T1566.002"},
		},
	}

	if sender, ok := raw["sender"].(string); ok {
		event.Normalized["sender"] = sender
	}
	if subject, ok := raw["subject"].(string); ok {
		event.Normalized["subject"] = subject
	}
	if phishingType, ok := raw["phishing_type"].(string); ok {
		event.Normalized["phishing_type"] = phishingType
	}

	event.Risk = &models.RiskScore{
		Score:   65,
		Factors: []string{"phishing_email", "quishing"},
	}

	return event, nil
}

type ZKNormalizer struct{}

func (n *ZKNormalizer) Normalize(raw map[string]interface{}) (*models.XDREvent, error) {
	event := &models.XDREvent{
		EventID:    "evt_" + uuid.New().String()[:12],
		Source:     "zk",
		EventType:  "zk.device.attestation.failed",
		Severity:   "critical",
		ObservedAt: time.Now().UTC(),
		Raw:        raw,
		Normalized: make(map[string]interface{}),
		Trace: &models.TraceInfo{
			Collector:     "zk-device-trust",
			Pipeline:      "redis-streams:xdr.events",
			SchemaVersion: "xdr-event-v0.1",
		},
		MITRE: &models.MITREInfo{
			Tactics:    []string{"persistence", "defense-evasion"},
			Techniques: []string{"T1542.001", "T1553.006"},
		},
	}

	if deviceID, ok := raw["device_id"].(string); ok {
		event.DeviceID = deviceID
	}
	if status, ok := raw["attestation_result"].(string); ok {
		event.Normalized["attestation_status"] = status
	}
	if delta, ok := raw["trust_score_delta"].(float64); ok {
		event.Normalized["trust_score_delta"] = delta
	}

	event.Risk = &models.RiskScore{
		Score:   90,
		Factors: []string{"zk_attestation_failed", "low_device_trust"},
	}

	return event, nil
}

type EndpointNormalizer struct{}

func (n *EndpointNormalizer) Normalize(raw map[string]interface{}) (*models.XDREvent, error) {
	event := &models.XDREvent{
		EventID:    "evt_" + uuid.New().String()[:12],
		Source:     "endpoint",
		EventType:  "endpoint.process.suspicious",
		Severity:   "medium",
		ObservedAt: time.Now().UTC(),
		Raw:        raw,
		Normalized: make(map[string]interface{}),
		Trace: &models.TraceInfo{
			Collector:     "ebpf-collector",
			Pipeline:      "redis-streams:xdr.events",
			SchemaVersion: "xdr-event-v0.1",
		},
		MITRE: &models.MITREInfo{
			Tactics:    []string{"execution", "privilege-escalation"},
			Techniques: []string{"T1059", "T1548"},
		},
	}

	if processName, ok := raw["process_name"].(string); ok {
		event.Normalized["process_name"] = processName
	}
	if pid, ok := raw["pid"].(float64); ok {
		event.Normalized["pid"] = pid
	}
	if cmdline, ok := raw["command_line"].(string); ok {
		event.Normalized["command_line"] = cmdline
	}

	event.Risk = &models.RiskScore{
		Score:   55,
		Factors: []string{"suspicious_process", "ebpf_detection"},
	}

	return event, nil
}

func ParseRawEvent(data []byte) (map[string]interface{}, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
