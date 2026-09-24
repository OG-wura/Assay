package mechanics

import (
	"context"
	"strings"
)

// CapabilityCheck derives severity from the issuer's authorization flags.
//
// It is the only check that can set the capability base severity. It reports
// what the issuer is able to do, never who the issuer is.
type CapabilityCheck struct{}

// ID implements Check.
func (CapabilityCheck) ID() string { return "capability" }

// Describe implements Check.
func (CapabilityCheck) Describe() string {
	return "Maps the issuer's authorization flags to a capability severity: " +
		"what the issuer can do to a holder's balance. Says nothing about who " +
		"the issuer is or whether they are likely to use the power."
}

// Run implements Check.
//
// Severity is the highest single capability present, not a sum. auth_revocable
// is a protocol precondition for auth_clawback_enabled (CAP-0035: setting
// clawback without revocable fails with SET_OPTIONS_AUTH_REVOCABLE_REQUIRED),
// so a clawback-capable issuer necessarily also carries revocable. Scoring
// those as two independent signals would double-count a rule the protocol
// enforces, and would make every clawback asset look worse than it is by a
// margin that has nothing to do with its behaviour.
func (c CapabilityCheck) Run(_ context.Context, s *Subject) (Finding, error) {
	f := Finding{
		Check:    c.ID(),
		Title:    "Issuer capability",
		Severity: Clear,
		Evidence: []Evidence{},
	}

	if s.Stat == nil {
		f.Reasoning = "Asset not found on the ledger, so no issuer capability could be read."
		return f, nil
	}

	flags := s.Stat.Flags
	var mech Mechanic
	var powers []string

	if flags.AuthRequired {
		mech |= MechAuthRequired
		powers = append(powers, "decide who is allowed to hold it (auth_required)")
		f.Severity = Low
	}
	if flags.AuthRevocable {
		mech |= MechAuthRevocable
		powers = append(powers, "freeze your balance so you cannot move it (auth_revocable)")
		f.Severity = Medium
	}
	if flags.AuthClawbackEnabled {
		mech |= MechClawbackEnabled
		powers = append(powers, "confiscate your balance outright and burn it, "+
			"without your signature (auth_clawback_enabled)")
		f.Severity = High
	}
	if flags.AuthImmutable {
		mech |= MechFlagsLocked
	}
	f.Mechanics = mech

	f.Evidence = append(f.Evidence, Evidence{
		Source:      "horizon",
		URL:         horizonAssetURL(s.Asset),
		Claim:       "issuer flags: " + flagSummary(flags),
		RetrievedAt: s.StatFetchedAt,
	})

	var b strings.Builder
	if len(powers) == 0 {
		b.WriteString("The issuer holds no authorization flags. It cannot freeze, " +
			"confiscate, or gate this asset. ")
	} else {
		b.WriteString("The issuer can ")
		b.WriteString(joinPowers(powers))
		b.WriteString(". ")
	}

	// auth_immutable is not a power over holders; it fixes whether the power
	// set can change. Which direction that cuts depends entirely on what is
	// already set, so it is stated explicitly rather than scored.
	switch {
	case flags.AuthImmutable && flags.AuthClawbackEnabled:
		b.WriteString("These flags are locked permanently (auth_immutable): the " +
			"confiscation power can never be given up.")
	case flags.AuthImmutable:
		b.WriteString("These flags are locked permanently (auth_immutable), so the " +
			"issuer can never add confiscation or freeze powers later.")
	case flags.AuthClawbackEnabled:
		b.WriteString("The flags are not locked, so the issuer may change them, but " +
			"clawback already applies to trustlines opened now.")
	default:
		b.WriteString("The flags are not locked (auth_immutable is unset), so the " +
			"issuer may add freeze or confiscation powers in future. Under CAP-0035 " +
			"that would not reach trustlines that already exist, but it would apply " +
			"to any trustline opened after the change.")
	}
	f.Reasoning = b.String()

	return f, nil
}

func joinPowers(p []string) string {
	switch len(p) {
	case 1:
		return p[0]
	case 2:
		return p[0] + ", and " + p[1]
	default:
		return strings.Join(p[:len(p)-1], ", ") + ", and " + p[len(p)-1]
	}
}
