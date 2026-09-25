package temporal

import "github.com/use-assay/assay/internal/mechanics"

// Attribution names which axis moved severity between two observations.
//
// It is derived from the pair, not from the size or direction of the movement,
// because the two axes have different reliability and different implications: a
// capability move is a consensus-enforced change in what the issuer can do, and
// a reputation move is a curator changing its mind about who the issuer is.
// Collapsing them would hide exactly the distinction docs/severity-model.md
// exists to preserve.
type Attribution string

const (
	// AttributionNone means neither axis moved.
	AttributionNone Attribution = "none"
	// AttributionCapability means the capability base moved.
	AttributionCapability Attribution = "capability"
	// AttributionReputation means an escalation was gained or lost while the
	// capability base held still.
	AttributionReputation Attribution = "reputation"
	// AttributionBoth means both axes moved in the interval.
	AttributionBoth Attribution = "both"
)

// SeverityMovement is how severity moved between two observations, with the
// movement attributed to the axis that produced it.
type SeverityMovement struct {
	// BaseBefore/BaseAfter are the capability-only severities.
	BaseBefore mechanics.Severity `json:"base_before"`
	BaseAfter  mechanics.Severity `json:"base_after"`
	// Before/After are the final severities, after escalation.
	Before mechanics.Severity `json:"severity_before"`
	After  mechanics.Severity `json:"severity_after"`
	// Attribution names the axis that moved, if any. It is meaningful only when
	// State is Valid; on a comparison that could not be made it is left empty,
	// because an attribution would be an answer this function does not have.
	Attribution Attribution `json:"attribution"`
	State       State       `json:"state"`
	// Reason explains a non-Valid state in plain language.
	Reason string `json:"reason,omitempty"`
}

// SeverityTransition reports how severity and base severity moved between two
// observations and attributes the movement.
//
// Capability is read from base severity, which is capability-only by
// construction, and reputation from whether an escalation was in force (final
// severity above base). A movement of final severity alone is therefore never
// attributed to capability. DOGE is the worked example: base 0, final 4, every
// point of the escalation contributed by a curated listing and none of it by a
// flag (docs/attestation-run.md).
func SeverityTransition(from, to Observation) SeverityMovement {
	t := Between(from, to)
	m := SeverityMovement{State: t.State, Reason: t.Reason}
	if t.State != Valid {
		return m
	}
	m.BaseBefore, m.BaseAfter = t.BaseBefore, t.BaseAfter
	m.Before, m.After = t.SeverityBefore, t.SeverityAfter
	m.Attribution = t.Attribution
	return m
}

// attribution reports which axis moved a severity.
//
// Base severity is the capability axis because it is derived from flags alone.
// Final severity exceeds base only when a curator escalated the issuer, so a
// change in whether that escalation is in force is the reputation axis. This is
// what keeps a reputation-only move from ever being reported as capability: the
// capability test reads Base, and Base did not move.
func attribution(from, to Observation) Attribution {
	capabilityMoved := from.Base != to.Base
	reputationMoved := (from.Severity != from.Base) != (to.Severity != to.Base)

	switch {
	case capabilityMoved && reputationMoved:
		return AttributionBoth
	case capabilityMoved:
		return AttributionCapability
	case reputationMoved:
		return AttributionReputation
	default:
		return AttributionNone
	}
}
