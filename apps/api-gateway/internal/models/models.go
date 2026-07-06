package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type Tenant struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	Name      string    `gorm:"type:varchar(255);not null"`
	Slug      string    `gorm:"type:varchar(255);not null;uniqueIndex"`
	Plan      string    `gorm:"type:varchar(50);default:free"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type User struct {
	ID           uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID     *uuid.UUID `gorm:"type:uuid;index"`
	Email        string     `gorm:"type:varchar(255);not null;uniqueIndex"`
	PasswordHash string     `gorm:"type:varchar(512);not null"`
	Role         string     `gorm:"type:varchar(50);default:analyst"`
	MFAEnabled   bool       `gorm:"default:false"`
	CreatedAt    time.Time  `gorm:"autoCreateTime"`
	UpdatedAt    time.Time  `gorm:"autoUpdateTime"`
}

type Asset struct {
	ID              uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID        uuid.UUID      `gorm:"type:uuid;not null;index"`
	Name            string         `gorm:"type:varchar(255);not null"`
	AssetType       string         `gorm:"type:varchar(100);not null"`
	SerialNumber    string         `gorm:"type:varchar(255);uniqueIndex"`
	Manufacturer    string         `gorm:"type:varchar(255)"`
	Model           string         `gorm:"type:varchar(255)"`
	FirmwareVersion string         `gorm:"type:varchar(100)"`
	OS              string         `gorm:"type:varchar(100)"`
	IPAddresses     datatypes.JSON `gorm:"type:jsonb"`
	MACAddress      string         `gorm:"type:varchar(17)"`
	NetworkSegment  string         `gorm:"type:varchar(100)"`
	Criticality     string         `gorm:"type:varchar(50);default:medium"`
	Status          string         `gorm:"type:varchar(50);default:active"`
	TrustScore      float64        `gorm:"type:decimal(5,2);default:0"`
	LastSeenAt      *time.Time     `gorm:"type:timestamptz"`
	Metadata        datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt       time.Time      `gorm:"autoCreateTime"`
	UpdatedAt       time.Time      `gorm:"autoUpdateTime"`
	DeletedAt       gorm.DeletedAt `gorm:"index"`
}

type SecurityEvent struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID     uuid.UUID      `gorm:"type:uuid;not null;index"`
	EventID      string         `gorm:"type:varchar(255);not null;uniqueIndex"`
	Source       string         `gorm:"type:varchar(50);not null"`
	EventType    string         `gorm:"type:varchar(100);not null"`
	Severity     string         `gorm:"type:varchar(50);not null"`
	AssetID      *uuid.UUID     `gorm:"type:uuid;index"`
	DeviceID     *uuid.UUID     `gorm:"type:uuid;index"`
	IdentityID   *uuid.UUID     `gorm:"type:uuid;index"`
	ObservedAt   time.Time      `gorm:"type:timestamptz;not null"`
	Raw          datatypes.JSON `gorm:"type:jsonb"`
	Normalized   datatypes.JSON `gorm:"type:jsonb"`
	RiskScore    float64        `gorm:"type:decimal(5,2);default:0"`
	RiskFactors  datatypes.JSON `gorm:"type:jsonb"`
	Collector    string         `gorm:"type:varchar(100)"`
	Pipeline     string         `gorm:"type:varchar(100)"`
	SchemaVersion string        `gorm:"type:varchar(50)"`
	CreatedAt    time.Time      `gorm:"autoCreateTime"`
}

type Incident struct {
	ID             uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID       uuid.UUID      `gorm:"type:uuid;not null;index"`
	Title          string         `gorm:"type:varchar(500);not null"`
	Description    string         `gorm:"type:text"`
	IncidentType   string         `gorm:"type:varchar(100);not null"`
	Severity       string         `gorm:"type:varchar(50);not null"`
	Status         string         `gorm:"type:varchar(50);default:open"`
	RiskScore      float64        `gorm:"type:decimal(5,2);default:0"`
	Evidence       datatypes.JSON `gorm:"type:jsonb"`
	AssignedTo     *uuid.UUID     `gorm:"type:uuid"`
	AssignedAt     *time.Time     `gorm:"type:timestamptz"`
	ResolvedAt     *time.Time     `gorm:"type:timestamptz"`
	PlaybookID     *uuid.UUID     `gorm:"type:uuid"`
	MITRETactics   datatypes.JSON `gorm:"type:jsonb"`
	MITRETechniques datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt      time.Time      `gorm:"autoCreateTime"`
	UpdatedAt      time.Time      `gorm:"autoUpdateTime"`
}

type Playbook struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID    *uuid.UUID     `gorm:"type:uuid;index"`
	Name        string         `gorm:"type:varchar(255);not null"`
	Description string         `gorm:"type:text"`
	Version     string         `gorm:"type:varchar(50);default:0.1.0"`
	TriggerType string         `gorm:"type:varchar(100)"`
	TriggerConfig datatypes.JSON `gorm:"type:jsonb"`
	Conditions  datatypes.JSON `gorm:"type:jsonb"`
	Actions     datatypes.JSON `gorm:"type:jsonb"`
	Approval    datatypes.JSON `gorm:"type:jsonb"`
	IsActive    bool           `gorm:"default:true"`
	CreatedAt   time.Time      `gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `gorm:"autoUpdateTime"`
}

type CTIIndicator struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID    *uuid.UUID     `gorm:"type:uuid;index"`
	IndicatorID string         `gorm:"type:varchar(255);not null;uniqueIndex"`
	Type        string         `gorm:"type:varchar(50);not null"`
	Value       string         `gorm:"type:varchar(2048);not null"`
	Confidence  int            `gorm:"default:0"`
	Source      string         `gorm:"type:varchar(255)"`
	TLP         string         `gorm:"type:varchar(50);default:amber"`
	FirstSeen   *time.Time     `gorm:"type:timestamptz"`
	LastSeen    *time.Time     `gorm:"type:timestamptz"`
	Tags        datatypes.JSON `gorm:"type:jsonb"`
	MITRETactics datatypes.JSON `gorm:"type:jsonb"`
	Description string         `gorm:"type:text"`
	IsActive    bool           `gorm:"default:true"`
	CreatedAt   time.Time      `gorm:"autoCreateTime"`
	UpdatedAt   time.Time      `gorm:"autoUpdateTime"`
}

type ZKProof struct {
	ID             uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID       uuid.UUID      `gorm:"type:uuid;not null;index"`
	AssetID        uuid.UUID      `gorm:"type:uuid;not null;index"`
	ProofID        string         `gorm:"type:varchar(255);not null;uniqueIndex"`
	ProofSystem    string         `gorm:"type:varchar(50);not null"`
	CircuitType    string         `gorm:"type:varchar(100);not null"`
	ProofData      datatypes.JSON `gorm:"type:jsonb"`
	PublicInputs   datatypes.JSON `gorm:"type:jsonb"`
	Status         string         `gorm:"type:varchar(50);default:pending"`
	VerifiedAt     *time.Time     `gorm:"type:timestamptz"`
	TrustScoreDelta float64       `gorm:"type:decimal(5,2);default:0"`
	CreatedAt      time.Time      `gorm:"autoCreateTime"`
}

type AuditLog struct {
	ID         uuid.UUID      `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID   *uuid.UUID     `gorm:"type:uuid;index"`
	UserID     *uuid.UUID     `gorm:"type:uuid;index"`
	Action     string         `gorm:"type:varchar(100);not null"`
	Resource   string         `gorm:"type:varchar(100);not null"`
	ResourceID string         `gorm:"type:varchar(255)"`
	StatusCode int            `gorm:"default:0"`
	RequestIP  string         `gorm:"type:varchar(45)"`
	UserAgent  string         `gorm:"type:text"`
	Details    datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt  time.Time      `gorm:"autoCreateTime"`
}

type APIKey struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey;default:gen_random_uuid()"`
	TenantID  uuid.UUID  `gorm:"type:uuid;not null;index"`
	KeyHash   string     `gorm:"type:varchar(512);not null"`
	Name      string     `gorm:"type:varchar(255);not null"`
	Scopes    string     `gorm:"type:text"`
	ExpiresAt *time.Time `gorm:"type:timestamptz"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
}
