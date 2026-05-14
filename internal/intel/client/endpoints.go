package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

func (c *IntelClient) VerifyLicense(ctx context.Context, req *LicenseVerifyReq) (*LicenseVerifyResp, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal license verify req: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/v1/license/verify", bytesReader(body))
	if err != nil {
		return nil, fmt.Errorf("create license verify req: %w", err)
	}

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, &IntelError{Code: fmt.Sprintf("http_%d", resp.StatusCode), Message: string(respBody), Retryable: resp.StatusCode >= 500}
	}

	var result LicenseVerifyResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode license verify resp: %w", err)
	}
	return &result, nil
}

func (c *IntelClient) GetVersions(ctx context.Context) (*VersionsResp, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/api/v1/client/sync/versions", nil)
	if err != nil {
		return nil, fmt.Errorf("create versions req: %w", err)
	}

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResp(resp)
	}

	var result VersionsResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode versions resp: %w", err)
	}
	return &result, nil
}

func (c *IntelClient) SyncData(ctx context.Context, dataType, sinceVersion string, limit int) (*SyncResp, error) {
	url := fmt.Sprintf("%s/api/v1/client/sync/%s?since_version=%s&limit=%d", c.serverURL, dataType, sinceVersion, limit)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create sync req: %w", err)
	}

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResp(resp)
	}

	var result SyncResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode sync resp: %w", err)
	}
	return &result, nil
}

func (c *IntelClient) UploadEvents(ctx context.Context, req *UploadReq) (*UploadResp, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal upload req: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/v1/client/upload/events", bytesReader(body))
	if err != nil {
		return nil, fmt.Errorf("create upload req: %w", err)
	}

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResp(resp)
	}

	var result UploadResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode upload resp: %w", err)
	}
	return &result, nil
}

func (c *IntelClient) PollEmergency(ctx context.Context, since time.Time) (*EmergencyResp, error) {
	url := fmt.Sprintf("%s/api/v1/client/emergency/poll?since=%s", c.serverURL, since.UTC().Format(time.RFC3339))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create emergency req: %w", err)
	}

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseErrorResp(resp)
	}

	var result EmergencyResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode emergency resp: %w", err)
	}
	return &result, nil
}

func (c *IntelClient) HealthCheck(ctx context.Context) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.serverURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("create health check req: %w", err)
	}

	resp, err := c.doRequest(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: status %d", resp.StatusCode)
	}
	return nil
}

func parseErrorResp(resp *http.Response) error {
	body, _ := io.ReadAll(resp.Body)
	return &IntelError{
		Code:      fmt.Sprintf("http_%d", resp.StatusCode),
		Message:   string(body),
		Retryable: resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests,
	}
}
