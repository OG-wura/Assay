package temporal

import "github.com/use-assay/assay/internal/mechanics"

// CapabilityMask is the set of mechanic bits that are powers an issuer holds
// over a holder's balance.
//
// Only bits 0-2 are capabilities. The bit positions are part of the contract ABI
// (internal/mechanics/severity.go), and the separation is deliberate, so this
// mask names the three constants rather than spelling a literal — one place to
// get the positions right instead of two:
//
//   - bit 3, auth_immutable, locks the flag set. It is a power over the flags,
//     not over a holder, and which direction it cuts depends on what is already
//     set, so it is not a capability.
//   - bits 4-5, domain_unverified and blocklisted, are reported-only signals.
//     They say who the issuer is or what a curator determined, not what the
//     issuer can do. They can move severity between observations through
//     escalation, but they are not capability transitions.
//   - bits 6-7 describe one holder's trustline, not the issuer's capability,
//     and are holder-specific by construction.
const CapabilityMask = mechanics.MechAuthRequired |
	mechanics.MechAuthRevocable |
	mechanics.MechClawbackEnabled

// CapabilityDelta is a directional capability answer: which capability bits
// changed in the direction asked about.
//
// State is what makes an empty Delta distinguishable from no answer. A
// comparison that was made and found nothing returns Valid with Bits == 0; a
// comparison that could not be made returns Unknown or Missing. A caller that
// reads only Bits collapses the two, which is the failure this type exists to
// prevent.
type CapabilityDelta struct {
	Bits  mechanics.Mechanic `json:"bits"`
	Names []string           `json:"names"`
	State State              `json:"state"`
	// Reason explains a non-Valid state in plain language.
	Reason string `json:"reason,omitempty"`
}

// Added returns the capability bits present in the later observation and absent
// in the earlier one.
//
// This is the alarming direction. Under CAP-0035 a flag the issuer adds does not
// reach trustlines that already exist, but it applies to every trustline opened
// afterwards, so the answer changes for new holders with no announcement and
// nothing an existing holder can see move. It is built on Between, so it
// inherits the same ordering and the same State semantics.
func Added(from, to Observation) CapabilityDelta {
	return delta(Between(from, to), true)
}

// Removed returns the capability bits present in the earlier observation and
// absent in the later one.
//
// This is the reassuring direction, and the one most likely to be over-read. A
// removal does not undo exposure. Under CAP-0035 a trustline that inherited
// clawback at creation keeps is_clawback_enabled even after the issuer clears
// the account flag, and a balance already frozen or confiscated is not restored
// — dropping the power changes what a trustline opened after the change
// inherits, and nothing about one opened before it. The same asymmetry is why
// removal is reported as a fact about capability and never as a statement that
// past exposure has been cancelled.
//
// auth_immutable interacts with this directly. If the later observation carries
// auth_immutable, a removal is permanent: the issuer can never re-add the power.
// If the earlier observation carried it, the removal should not have been
// possible at all, and a consumer should treat the pair as suspect rather than
// as a clean removal. Either way auth_immutable is not itself a capability, so
// it never appears in the returned bits.
func Removed(from, to Observation) CapabilityDelta {
	return delta(Between(from, to), false)
}

// delta projects the capability half of a transition in one direction. A
// non-Valid transition carries no bits and the reason it could not be derived.
func delta(t Transition, added bool) CapabilityDelta {
	d := CapabilityDelta{State: t.State, Reason: t.Reason}
	if t.State != Valid {
		return d
	}
	if added {
		d.Bits, d.Names = t.Added, t.AddedNames
	} else {
		d.Bits, d.Names = t.Removed, t.RemovedNames
	}
	return d
}
