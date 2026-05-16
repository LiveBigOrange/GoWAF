package sync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"gowaf/internal/intel/client"
	"gowaf/internal/intel/store"
	"gowaf/internal/infra/logger"
)

type GeoIPSyncer struct {
	client   *client.IntelClient
	store    *store.Store
	mmdbPath string
}

func NewGeoIPSyncer(c *client.IntelClient, s *store.Store, mmdbPath string) *GeoIPSyncer {
	if mmdbPath == "" {
		mmdbPath = "GeoLite2-City.mmdb"
	}
	return &GeoIPSyncer{
		client:   c,
		store:    s,
		mmdbPath: mmdbPath,
	}
}

func (g *GeoIPSyncer) SyncGeoIP() error {
	logger.Info("starting GeoIP MMDB sync")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	resp, err := g.client.SyncData(ctx, "geoip", "", 0)
	if err != nil {
		return fmt.Errorf("geoip sync request failed: %w", err)
	}

	downloadURL := ""
	checksum := ""
	if len(resp.Added) > 0 {
		if data, ok := resp.Added[0].Data.(map[string]interface{}); ok {
			if u, ok := data["download_url"].(string); ok {
				downloadURL = u
			}
			if c, ok := data["checksum"].(string); ok {
				checksum = c
			}
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("geoip sync: no download_url in response")
	}

	tmpPath := g.mmdbPath + ".tmp"
	backupPath := g.mmdbPath + ".bak"

	if err := g.downloadFile(downloadURL, tmpPath); err != nil {
		return fmt.Errorf("geoip download failed: %w", err)
	}

	if checksum != "" {
		if err := g.verifyChecksum(tmpPath, checksum); err != nil {
			os.Remove(tmpPath)
			return fmt.Errorf("geoip checksum verification failed: %w", err)
		}
	}

	if _, err := os.Stat(g.mmdbPath); err == nil {
		if err := os.Rename(g.mmdbPath, backupPath); err != nil {
			logger.Error("failed to backup existing MMDB", "err", err)
		}
	}

	if err := os.Rename(tmpPath, g.mmdbPath); err != nil {
		g.rollback(backupPath)
		return fmt.Errorf("geoip hot-swap failed: %w", err)
	}

	logger.Info("GeoIP MMDB hot-swapped successfully")

	if g.store != nil {
		_ = g.store.AddConnectionLog("geoip_sync", "GeoIP MMDB updated")
	}

	return nil
}

func (g *GeoIPSyncer) downloadFile(url, dest string) error {
	httpClient := &http.Client{Timeout: 5 * time.Minute}
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(f, resp.Body)
	return err
}

func (g *GeoIPSyncer) verifyChecksum(path, expected string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])
	if actual != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func (g *GeoIPSyncer) rollback(backupPath string) {
	if _, err := os.Stat(backupPath); err == nil {
		if err := os.Rename(backupPath, g.mmdbPath); err != nil {
			logger.Error("geoip rollback failed", "err", err)
		} else {
			logger.Info("rolled back to previous GeoIP MMDB")
		}
	}
}
