package temporal_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// The concrete scenario the severity model already describes: an issuer that can
// already freeze a balance adds clawback. Under CAP-0035 the new flag does not
// reach trustlines that already exist, but every trustline opened afterwards
// inherits it, so the answer changes for new holders with no announcement.
func TestAdditionClawbackAdded(t *testing.T) {
	before := obs(at(1), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)
	after := obs(at(2), mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)

	got := temporal.Added(before, after)

	if got.State != temporal.Valid {
		t.Fatalf("state = %q, want %q: %s", got.State, temporal.Valid, got.Reason)
	}
	if got.Bits != mechanics.MechClawbackEnabled {
		t.Fatalf("added = %v, want [auth_clawback_enabled]", got.Names)
	}
	if !slices.Equal(got.Names, []string{"auth_clawback_enabled"}) {
		t.Fatalf("added names = %v", got.Names)
	}
}

// Enabling clawback requires auth_revocable (CAP-0035), so an issuer going from
// clear straight to clawback genuinely gains two capability bits. Both are real
// powers and both are reported; this is a difference, not a sum, so it does not
// double-count the precondition.
func TestAdditionFromClearReportsEveryNewBit(t *testing.T) {
	got := temporal.Added(
		obs(at(1), 0, mechanics.Clear, mechanics.Clear),
		obs(at(2), mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled, mechanics.High, mechanics.High),
	)

	want := mechanics.MechAuthRevocable | mechanics.MechClawbackEnabled
	if got.Bits != want {
		t.Fatalf("added = %v, want revocable and clawback", got.Names)
	}
}

// An empty answer and no answer must be separable by a program, not only by a
// reader. Valid with no bits is "we looked and nothing moved".
func TestAdditionNoChange(t *testing.T) {
	before := obs(at(1), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)
	after := obs(at(2), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)

	got := temporal.Added(before, after)

	if got.State != temporal.Valid {
		t.Fatalf("state = %q, want %q", got.State, temporal.Valid)
	}
	if got.Bits != 0 {
		t.Fatalf("added = %v, want none", got.Names)
	}
	if got.Reason != "" {
		t.Fatalf("a valid no-change answer must not carry a failure reason: %q", got.Reason)
	}
}

// An undetermined earlier observation is not a clean baseline. A bit absent
// there may only be unread, so the addition cannot be asserted.
func TestAdditionUndeterminedEarlierObservation(t *testing.T) {
	before := obs(at(1), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)
	before.Undetermined = true
	before.UndeterminedChecks = []string{"reputation"}
	after := obs(at(2), mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)

	got := temporal.Added(before, after)

	if got.State != temporal.Unknown {
		t.Fatalf("state = %q, want %q", got.State, temporal.Unknown)
	}
	if got.Bits != 0 {
		t.Fatalf("an undetermined comparison returned bits %v", got.Names)
	}
	if !strings.Contains(got.Reason, "reputation") {
		t.Fatalf("reason does not name the incomplete check: %q", got.Reason)
	}
}

// Bits 3 and 4-7 are not capabilities. A change in any of them is not a
// capability addition even when it moves severity, which is exactly how a
// reputation-only escalation must render.
func TestAdditionReportedOnlyBitIsNotCapability(t *testing.T) {
	before := obs(at(1), 0, mechanics.Clear, mechanics.Clear)
	// blocklisted and domain_unverified are reported-only (bits 4-5),
	// auth_immutable fixes the flag set (bit 3), and the trustline bits (6-7)
	// describe one holder rather than the issuer.
	after := obs(at(2),
		mechanics.MechFlagsLocked|mechanics.MechDomainUnverified|mechanics.MechBlocklisted|
			mechanics.MechTrustlineClawbackEnabled|mechanics.MechTrustlineDeauthorized,
		mechanics.Clear, mechanics.Critical)

	got := temporal.Added(before, after)

	if got.State != temporal.Valid {
		t.Fatalf("state = %q, want %q", got.State, temporal.Valid)
	}
	if got.Bits != 0 {
		t.Fatalf("non-capability bits reported as capability additions: %v", got.Names)
	}
}

// The reverse direction. An issuer drops clawback while keeping revocable.
func TestRemovalClawbackRemoved(t *testing.T) {
	before := obs(at(1), mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)
	after := obs(at(2), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)

	got := temporal.Removed(before, after)

	if got.State != temporal.Valid {
		t.Fatalf("state = %q, want %q: %s", got.State, temporal.Valid, got.Reason)
	}
	if got.Bits != mechanics.MechClawbackEnabled {
		t.Fatalf("removed = %v, want [auth_clawback_enabled]", got.Names)
	}
}

// auth_immutable is not a capability, so it never appears in Removed even when
// it changes across the pair. The scenario — clawback cleared, then the flag set
// locked — is the one where the removal is permanent, which the prose states and
// this test pins structurally.
func TestRemovalWithAuthImmutableSet(t *testing.T) {
	before := obs(at(1), mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)
	after := obs(at(2), mechanics.MechAuthRevocable|mechanics.MechFlagsLocked, mechanics.Medium, mechanics.Medium)

	got := temporal.Removed(before, after)

	if got.State != temporal.Valid {
		t.Fatalf("state = %q, want %q: %s", got.State, temporal.Valid, got.Reason)
	}
	if got.Bits != mechanics.MechClawbackEnabled {
		t.Fatalf("removed = %v, want [auth_clawback_enabled]", got.Names)
	}
	if got.Bits&mechanics.MechFlagsLocked != 0 {
		t.Fatalf("auth_immutable reported as a removed capability: %v", got.Names)
	}
	if slices.Contains(got.Names, "auth_immutable") {
		t.Fatalf("auth_immutable reported as a removed capability: %v", got.Names)
	}
}

// An undetermined later observation cannot be read as a clean removal.
func TestRemovalUndeterminedObservation(t *testing.T) {
	before := obs(at(1), mechanics.MechAuthRevocable|mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)
	after := obs(at(2), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)
	after.Undetermined = true
	after.UndeterminedChecks = []string{"reputation"}

	got := temporal.Removed(before, after)

	if got.State != temporal.Unknown {
		t.Fatalf("state = %q, want %q", got.State, temporal.Unknown)
	}
	if got.Bits != 0 {
		t.Fatalf("an undetermined comparison returned bits %v", got.Names)
	}
	if !strings.Contains(got.Reason, "later observation") {
		t.Fatalf("reason does not identify the incomplete side: %q", got.Reason)
	}
}
