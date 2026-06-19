package telemetry

import "testing"

// TestResolveModeOfflineWins verifies CHAINSAW_OFFLINE=1 forces
// ModeDisabled regardless of the self-hosted/cloud or the legacy
// CHAINSAW_TELEMETRY_ENABLED knob. The air-gap umbrella flag must
// suppress every phone-home code path.
func TestResolveModeOfflineWins(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE", "1")
	t.Setenv("CHAINSAW_TELEMETRY_ENABLED", "1")
	t.Setenv("CHAINSAW_TELEMETRY_DISABLED", "")
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "")
	if got := ResolveMode(); got != ModeDisabled {
		t.Fatalf("ResolveMode with CHAINSAW_OFFLINE=1 = %v, want ModeDisabled", got)
	}
}

// TestResolveModeDebugBeatsOffline verifies ModeDebug still wins so
// developers inspecting events locally aren't surprised by an offline
// flag flipping them to fully silent.
func TestResolveModeDebugBeatsOffline(t *testing.T) {
	t.Setenv("CHAINSAW_TELEMETRY_DEBUG", "1")
	t.Setenv("CHAINSAW_OFFLINE", "1")
	if got := ResolveMode(); got != ModeDebug {
		t.Fatalf("ResolveMode with DEBUG=1 OFFLINE=1 = %v, want ModeDebug", got)
	}
}
