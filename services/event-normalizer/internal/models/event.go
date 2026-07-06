package models

import "time"

type XDREvent struct {
	EventID       string                 `json:"event_id"`
	TenantID      string                 `json:"tenant_id"`
	Source        string                 `json:"source"`
	EventType     string                 `json:"event_type"`
	Severity      string                 `json:"severity"`
	AssetID       string                 `json:"asset_id,omitempty"`
	DeviceID      string                 `json:"device_id,omitempty"`
	IdentityID    string                 `json:"identity_id,omitempty"`
	ObservedAt    time.Time              `json:"observed_at"`
	Raw           map[string]interface{} `json:"raw,omitempty"`
	Normalized    map[string]interface{} `json:"normalized,omitempty"`
	Risk          *RiskScore             `json:"risk,omitempty"`
	Trace         *TraceInfo             `json:"trace,omitempty"`
	MITRE         *MITREInfo             `json:"mitre,omitempty"`
}

type RiskScore struct {
	Score   float64  `json:"score"`
	Factors []string `json:"factors"`
}

type TraceInfo struct {
	Collector     string `json:"collector"`
	Pipeline      string `json:"pipeline"`
	SchemaVersion string `json:"schema_version"`
}

type MITREInfo struct {
	Tactics    []string `json:"tactics"`
	Techniques []string `json:"techniques"`
}
