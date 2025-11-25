//go:build testing

// Package zk provides testing helpers that are excluded from production builds.
// This file is only compiled when the "testing" build tag is present.
package zk

// ClearVerifierForTesting clears the global verifier state.
// SECURITY: This function is ONLY available in test builds (requires -tags=testing).
// In production builds, the verifier is immutable once initialized.
//
// WARNING: Do not call this in production code. The verifier is intentionally
// immutable to prevent VK replacement attacks.
func ClearVerifierForTesting() {
	globalState.mu.Lock()
	defer globalState.mu.Unlock()
	globalState.verifier = nil
	globalState.initialized = false
}

