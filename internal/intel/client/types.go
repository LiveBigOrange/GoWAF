package client

import "bytes"

func bytesReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}

type LicenseVerifyReq struct {
	LicenseKey string `json:"license_key"`
	InstanceID string `json:"instance_id"`
	Hostname   string `json:"hostname,omitempty"`
	Version    string `json:"version,omitempty"`
	IP         string `json:"ip,omitempty"`
}

type LicenseVerifyResp struct {
	Valid            bool           `json:"valid"`
	Tier             string         `json:"tier"`
	TierLabel        string         `json:"tier_label,omitempty"`
	ExpiresAt        string         `json:"expires_at"`
	GraceEndsAt      string         `json:"grace_ends_at"`
	SyncIntervalSecs int            `json:"sync_interval_secs"`
	Features         []string       `json:"features"`
	FeaturesLabel    []string       `json:"features_label,omitempty"`
	InstanceLimit    int            `json:"instance_limit"`
	InstancesUsed    int            `json:"instances_used"`
	Instances        []InstanceInfo `json:"instances,omitempty"`
}

type InstanceInfo struct {
	InstanceID string `json:"instance_id"`
	Hostname   string `json:"hostname"`
	LastSeen   string `json:"last_seen"`
	Status     string `json:"status"`
}

type SyncResp struct {
	DataType       string        `json:"data_type"`
	CurrentVersion string        `json:"current_version"`
	SyncInterval   int           `json:"sync_interval_secs"`
	Added          []SyncItem    `json:"added"`
	Modified       []SyncItem    `json:"modified"`
	Deleted        []DeletedItem `json:"deleted"`
	DeletedIDs     []string      `json:"deleted_ids,omitempty"`
	TotalAvailable int           `json:"total_available"`
	HasMore        bool          `json:"has_more"`
}

type DeletedItem struct {
	IntelID string `json:"intel_id"`
	Reason  string `json:"reason"`
}

type SyncItem struct {
	IntelID    string      `json:"intel_id"`
	Data       interface{} `json:"data"`
	OldVersion int         `json:"old_version"`
}

type UploadReq struct {
	DataType   string        `json:"data_type"`
	InstanceID string        `json:"instance_id,omitempty"`
	Events     []interface{} `json:"events"`
}

type UploadResp struct {
	Accepted       int     `json:"accepted"`
	Rejected       int     `json:"rejected"`
	CreditsAwarded int     `json:"credits_awarded"`
	QualityScore   float64 `json:"quality_score"`
}

type EmergencyResp struct {
	Rules      []EmergencyRule `json:"rules"`
	ServerTime string          `json:"server_time"`
}

type EmergencyRule struct {
	ID        string `json:"id"`
	DataType  string `json:"data_type"`
	IntelID   string `json:"intel_id"`
	Payload   string `json:"payload"`
	Severity  string `json:"severity"`
	Reason    string `json:"reason"`
	ExpiresAt string `json:"expires_at"`
}

type VersionsResp struct {
	Versions []DataTypeVersion `json:"versions"`
}

type DataTypeVersion struct {
	DataType       string `json:"data_type"`
	CurrentVersion string `json:"current_version"`
	UpdatedAt      string `json:"updated_at"`
}
