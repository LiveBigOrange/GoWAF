package store

import (
	"database/sql"
	"fmt"
	"time"
)

type SecureConfig struct {
	ServerURL           string
	LicenseKeyEncrypted string
	LicenseTier         string
	LicenseStatus       string
	LicenseExpiresAt    *time.Time
	UpdatedAt           time.Time
}

func (s *Store) GetSecureConfig() (*SecureConfig, error) {
	var cfg SecureConfig
	err := s.db.QueryRow(
		"SELECT server_url, license_key_encrypted, license_tier, license_status, license_expires_at, updated_at FROM threat_intel_config WHERE id=1",
	).Scan(&cfg.ServerURL, &cfg.LicenseKeyEncrypted, &cfg.LicenseTier, &cfg.LicenseStatus, &cfg.LicenseExpiresAt, &cfg.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secure config: %w", err)
	}
	return &cfg, nil
}

func (s *Store) GetLicenseKey() (string, error) {
	cfg, err := s.GetSecureConfig()
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", nil
	}
	return DecryptAESGCM(cfg.LicenseKeyEncrypted)
}

func (s *Store) SaveLicenseKey(licenseKey string) error {
	encrypted, err := EncryptAESGCM(licenseKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt license key: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO threat_intel_config (id, license_key_encrypted, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(id) DO UPDATE SET license_key_encrypted=excluded.license_key_encrypted, updated_at=CURRENT_TIMESTAMP`,
		encrypted,
	)
	if err != nil {
		return fmt.Errorf("failed to save license key: %w", err)
	}
	return nil
}

func (s *Store) SaveServerURL(serverURL string) error {
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_config (id, server_url, updated_at) VALUES (1, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(id) DO UPDATE SET server_url=excluded.server_url, updated_at=CURRENT_TIMESTAMP`,
		serverURL,
	)
	if err != nil {
		return fmt.Errorf("failed to save server url: %w", err)
	}
	return nil
}

func (s *Store) SaveLicenseStatus(tier, status string, expiresAt *time.Time) error {
	_, err := s.db.Exec(
		`INSERT INTO threat_intel_config (id, license_tier, license_status, license_expires_at, updated_at) VALUES (1, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(id) DO UPDATE SET license_tier=excluded.license_tier, license_status=excluded.license_status, license_expires_at=excluded.license_expires_at, updated_at=CURRENT_TIMESTAMP`,
		tier, status, expiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to save license status: %w", err)
	}
	return nil
}

func (s *Store) MigrateFromConfig(serverURL, licenseKey string) error {
	encrypted, err := EncryptAESGCM(licenseKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt license key: %w", err)
	}
	_, err = s.db.Exec(
		`INSERT INTO threat_intel_config (id, server_url, license_key_encrypted, updated_at) VALUES (1, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(id) DO UPDATE SET server_url=excluded.server_url, license_key_encrypted=excluded.license_key_encrypted, updated_at=CURRENT_TIMESTAMP`,
		serverURL, encrypted,
	)
	if err != nil {
		return fmt.Errorf("failed to migrate config to db: %w", err)
	}
	return nil
}
