package temporal_test

import (
	"testing"

	"github.com/use-assay/assay/internal/mechanics"
	"github.com/use-assay/assay/internal/temporal"
)

// The DOGE shape: base severity 0, final severity 4, with no capability bit
// behind any of it. A curated listing appeared; no flag did. Attributing any of
// this to capability would be the exact error docs/severity-model.md exists to
// prevent.
func TestSeverityReputationOnlyEscalation(t *testing.T) {
	before := obs(at(1), 0, mechanics.Clear, mechanics.Clear)
	after := obs(at(2), mechanics.MechBlocklisted, mechanics.Clear, mechanics.Critical)

	got := temporal.SeverityTransition(before, after)

	if got.State != temporal.Valid {
		t.Fatalf("state = %q, want %q: %s", got.State, temporal.Valid, got.Reason)
	}
	if got.BaseBefore != mechanics.Clear || got.BaseAfter != mechanics.Clear {
		t.Fatalf("base moved from %v to %v; there was no capability change", got.BaseBefore, got.BaseAfter)
	}
	if got.Before != mechanics.Clear || got.After != mechanics.Critical {
		t.Fatalf("severity = %v -> %v, want clear -> critical", got.Before, got.After)
	}
	if got.Attribution != temporal.AttributionReputation {
		t.Fatalf("attribution = %q, want %q", got.Attribution, temporal.AttributionReputation)
	}
	if got.Attribution == temporal.AttributionCapability {
		t.Fatal("a reputation-only escalation was attributed to capability")
	}
}

// Capability moved and reputation did not: clawback added to an asset nothing
// has flagged.
func TestSeverityCapabilityOnlyMovement(t *testing.T) {
	before := obs(at(1), 0, mechanics.Clear, mechanics.Clear)
	after := obs(at(2), mechanics.MechClawbackEnabled, mechanics.High, mechanics.High)

	got := temporal.SeverityTransition(before, after)

	if got.Attribution != temporal.AttributionCapability {
		t.Fatalf("attribution = %q, want %q", got.Attribution, temporal.AttributionCapability)
	}
	if got.BaseBefore != mechanics.Clear || got.BaseAfter != mechanics.High {
		t.Fatalf("base = %v -> %v, want clear -> high", got.BaseBefore, got.BaseAfter)
	}
	if got.Before != mechanics.Clear || got.After != mechanics.High {
		t.Fatalf("severity = %v -> %v, want clear -> high", got.Before, got.After)
	}
}

// Both axes move in the same interval: the issuer gains freeze power and a
// curator starts flagging it.
func TestSeverityBothMove(t *testing.T) {
	before := obs(at(1), 0, mechanics.Clear, mechanics.Clear)
	after := obs(at(2), mechanics.MechAuthRevocable|mechanics.MechBlocklisted, mechanics.Medium, mechanics.Critical)

	got := temporal.SeverityTransition(before, after)

	if got.Attribution != temporal.AttributionBoth {
		t.Fatalf("attribution = %q, want %q", got.Attribution, temporal.AttributionBoth)
	}
	if got.BaseBefore != mechanics.Clear || got.BaseAfter != mechanics.Medium {
		t.Fatalf("base = %v -> %v, want clear -> medium", got.BaseBefore, got.BaseAfter)
	}
	if got.Before != mechanics.Clear || got.After != mechanics.Critical {
		t.Fatalf("severity = %v -> %v, want clear -> critical", got.Before, got.After)
	}
}

// Neither axis moved. This is a Valid answer with AttributionNone, which is not
// the same as a comparison that could not be made.
func TestSeverityNeitherMoves(t *testing.T) {
	before := obs(at(1), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)
	after := obs(at(2), mechanics.MechAuthRevocable, mechanics.Medium, mechanics.Medium)

	got := temporal.SeverityTransition(before, after)

	if got.State != temporal.Valid {
		t.Fatalf("state = %q, want %q", got.State, temporal.Valid)
	}
	if got.Attribution != temporal.AttributionNone {
		t.Fatalf("attribution = %q, want %q", got.Attribution, temporal.AttributionNone)
	}
}

// An undetermined observation yields no movement and no attribution, and says
// so rather than reporting a quiet none.
func TestSeverityUndeterminedIsNoAnswer(t *testing.T) {
	before := obs(at(1), 0, mechanics.Clear, mechanics.Clear)
	after := obs(at(2), mechanics.MechAuthRevocable|mechanics.MechBlocklisted, mechanics.Medium, mechanics.Critical)
	after.Undetermined = true
	after.UndeterminedChecks = []string{"reputation"}

	got := temporal.SeverityTransition(before, after)

	if got.State != temporal.Unknown {
		t.Fatalf("state = %q, want %q", got.State, temporal.Unknown)
	}
	if got.Attribution != "" {
		t.Fatalf("attribution = %q on a comparison that could not be made", got.Attribution)
	}
	if got.Reason == "" {
		t.Fatal("an unknown severity transition must carry a reason")
	}
}

// A reputation escalation being *cleared* is still a reputation movement, never
// a capability one, even though severity falls.
func TestSeverityEscalationClearedIsReputation(t *testing.T) {
	before := obs(at(1), mechanics.MechBlocklisted, mechanics.Clear, mechanics.Critical)
	after := obs(at(2), 0, mechanics.Clear, mechanics.Clear)

	got := temporal.SeverityTransition(before, after)

	if got.Attribution != temporal.AttributionReputation {
		t.Fatalf("attribution = %q, want %q", got.Attribution, temporal.AttributionReputation)
	}
}
