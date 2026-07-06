package config

import (
	"os"
	"path/filepath"
	"testing"
)

// A config written before the middleware knobs existed must still load with
// safe, non-zero limits rather than zero values that would disable the guards
// (or, for concurrency, reject every request).
func TestGetConfig_BackfillsMiddlewareDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	legacy := `{
		"http_listen_addr": "127.0.0.1:9999",
		"setup_dir": "./zk-setup",
		"chain_id": "qbtc-1",
		"request_timeout_sec": 300
	}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := GetConfig(path)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}

	if cfg.HTTPListenAddr != "127.0.0.1:9999" {
		t.Errorf("explicit value not preserved: %q", cfg.HTTPListenAddr)
	}
	if cfg.MaxConcurrentProofs != 2 {
		t.Errorf("MaxConcurrentProofs = %d, want default 2", cfg.MaxConcurrentProofs)
	}
	if cfg.MaxRequestBytes != 128<<10 {
		t.Errorf("MaxRequestBytes = %d, want default %d", cfg.MaxRequestBytes, 128<<10)
	}
}

func TestGetConfig_ExplicitValuesOverrideDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	full := `{
		"http_listen_addr": "0.0.0.0:8090",
		"setup_dir": "./zk-setup",
		"chain_id": "qbtc-1",
		"request_timeout_sec": 60,
		"max_concurrent_proofs": 8,
		"max_request_bytes": 4096,
		"auth_token": "secret"
	}`
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := GetConfig(path)
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}

	if cfg.MaxConcurrentProofs != 8 {
		t.Errorf("MaxConcurrentProofs = %d, want 8", cfg.MaxConcurrentProofs)
	}
	if cfg.MaxRequestBytes != 4096 {
		t.Errorf("MaxRequestBytes = %d, want 4096", cfg.MaxRequestBytes)
	}
	if cfg.AuthToken != "secret" {
		t.Errorf("AuthToken = %q, want %q", cfg.AuthToken, "secret")
	}
}
