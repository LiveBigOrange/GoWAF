package client

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"gowaf/internal/intel/config"
)

func buildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
		return tlsCfg, nil
	}

	if cfg.CACertPath != "" {
		caData, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read ca cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to append ca cert")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
