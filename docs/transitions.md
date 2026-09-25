# Capability transitions

Assay answers a prospective question: what can this issuer do to a trustline
opened now. That is exactly what the issuer's current flags answer, and it is the
right question for someone deciding whether to open one.

It cannot currently say **what changed**. That is the question a holder has after
they already hold the asset — and, more urgently, the question a prospective
holder has about an issuer that seemed clear last week.

This document defines how a change is represented. It is a design deliverable:
the representation lives in [`internal/temporal`](../internal/temporal), the
comparison functions are implemented there, and nothing here builds a detection
pipeline, a store, or an API surface. Those are separate issues, named under
[What this does not do](#what-this-does-not-do).

## What a transition is

A **transition** is an ordered pair of observations of the same asset, plus the
difference derived between them.

An **observation** is one asset's state at one time. It is a snapshot of fields
that [`mechanics.Report`](../internal/mechanics/mechanics.go) already computes —
this document introduces no new severity semantics, and neither does the code:

| Observation field | Source on `Report` | Meaning |
| --- | --- | --- |
| `asset` | `Report.Asset` | which asset was observed |
| `at` | `Report.ScannedAt` | when it was observed |
| `mechanics` | `Report.Mechanics` | the full bit set as read, capability and reported-only alike |
| `base_severity` | `Report.Base` | capability-only severity, before escalation |
| `severity` | `Report.Severity` | final severity, after escalation |
| `undetermined` | `Report.Undetermined` | whether a source it depends on failed to answer |
| `undetermined_checks` | `Report.UndeterminedChecks` | which checks could not complete |

The full bit set is carried rather than only the capability bits, so an
observation taken today can answer a question about a bit Assay does not compare
yet without being re-taken.

The derived difference has three parts:

| Part | Meaning |
| --- | --- |
| **added bits** | capability bits set in the later observation and clear in the earlier one |
| **removed bits** | capability bits set in the earlier observation and clear in the later one |
| **severity movement** | base and final severity before and after, attributed to the axis that moved |

The pair itself is kept, not just the difference. A difference alone cannot be
audited: a consumer has to be able to see what each observation said, and a
"cannot tell you" answer has to be explainable in terms of which input was
incomplete.

### Which bits are capabilities

Only bits **0-2** are capabilities — `auth_required`, `auth_revocable`,
`auth_clawback_enabled`. The separation is deliberate and the bits are contract
ABI ([severity model](severity-model.md#the-levels)):

- **Bit 3, `auth_immutable`**, locks the flag set. It is a power over the flags,
  not over a holder, and which direction it cuts depends on what is already set.
  It is not scored as a level and it is not a capability. Its interaction with a
  removal is stated in the `Removed` documentation.
- **Bits 4-5, `domain_unverified` and `blocklisted`**, are reported-only. They
  say who the issuer is or what a curator determined, not what the issuer can do.
  They can move severity between observations through escalation — that movement
  is reported, attributed to reputation — but they are never capability additions
  or removals.
- **Bits 6-7** describe one holder's trustline rather than the issuer, and are
  holder-specific by construction.

A mask over bits 0-2 is what makes "clawback was added" a statement about
capability and "the issuer got listed" a statement about reputation.

## Semantics

A transition is only an answer when the inputs support one. The three states are
distinct in the type, not only in prose:

- **valid** — two complete observations with distinct times. The difference is
  derived, and an empty difference means *no change*.
- **unknown** — one or both observations are undetermined, because a source that
  observation depends on did not answer. No transition can be derived, and that
  is reported. It is **not** "no change": a source that failed could have hidden
  exactly the change being asked about. This is the same rule the rest of the
  repo enforces — "'we could not check' and 'this is fine' are different answers
  and must never render the same" ([checks](checks.md)) — applied to a
  comparison instead of a single scan.
- **missing** — fewer than two observations exist. There is no second point to
  compare against.

Two further cases fall out of "distinct times":

- **A single observation yields no transition.** It is `missing`, and it is not
  "no change". An asset that has been seen once has not been observed to be
  stable; there is nothing to be stable *between*. See
  `TestSingleObservationIsMissingNotUnchanged`.
- **Two observations at the same instant are not ordered** and cannot define a
  direction. That is reported as `unknown` rather than silently treated as
  unchanged.

A caller therefore has to read the state, not only the bits. An empty difference
with state `valid` is a real answer; an empty difference with state `unknown` or
`missing` is the absence of one. The type exists to make that distinction
unmissable.

### Handling undetermined observations

Undetermined is not a property of the pair, it is a property of each
observation, and it propagates: if either side is undetermined the whole
comparison is `unknown`. The alternative — comparing the readable fields and
reporting the rest as unchanged — is the failure mode the project already fixed
once for reputation ([attestation run, Finding 1](attestation-run.md#finding-1)),
where an outage rendered as a clean result. Under CAP-0035 the direction of that
error is worst for additions: a bit that was never read looks absent, and absent
looks unchanged.

The reason text names the incomplete side and the checks that did not complete,
so "unknown" is never printed without the axis that was missing.

## Severity movement and attribution

Severity can move with no capability change at all. A blocklisting alone takes an
asset from `clear` to `critical`, which is exactly what
`DOGE-GA22IDJN…` demonstrates: base severity `0`, final severity `4`, entirely
reputation-driven ([attestation run](attestation-run.md)). A consumer needs to
know which axis moved, because the two have different implications and different
reliability.

Attribution is derived from the pair, not guessed from the size of the move:

- **capability** — `base_severity` moved. Base is capability-only by
  construction, so it is the capability axis.
- **reputation** — an escalation was gained or lost (`severity` above `base`)
  while `base_severity` held still.
- **both** — both happened in the interval.
- **none** — neither happened.

This is what makes a reputation-only move impossible to attribute to capability:
the capability test reads base severity, and base did not move.

## On-demand versus stored

**Decision: observations are stored; transitions are computed on demand.**

The representation is a pure function of two observations, and that is the whole
of it. Storing a computed transition would store a second source of truth beside
the pair it was derived from, which can disagree with that pair and cannot be
checked without it. Since the comparison is a handful of bitwise operations,
there is no cost being avoided.

Three properties make storing the observations and computing the transition the
better shape:

1. **The state depends on when the question is asked, not only on the data.**
   Whether a comparison is `valid`, `unknown`, or `missing` follows from the
   completeness of the observations. A stored transition would freeze an answer
   that may have been computed from a partial observation; recomputing from the
   stored pair keeps the state honest.
2. **Any pair, not just adjacent pairs.** With stored observations a caller can
   compare across an arbitrary interval — "was this clear when I opened my
   trustline, and what is it now" — without having precomputed every pair.
3. **One place to change.** When the severity model changes, the derived view
   changes with it. The stored `mechanics` bitset still supports recomputation of
   the capability half offline; the reputation half (`base_severity`,
   `severity`) records what was read at scan time and cannot be recomputed
   without re-reading a curator.

The consequence for storage, when it is built: an append-only sequence of
observations per asset, keyed by asset and ordered by time. A transition is a
view over that sequence, never a row in it. Building that store is out of scope
here.

## Reviewed against `internal/mechanics/mechanics.go`

The verification step for this design was to check it against the file the
comparison reads from, rather than against an idealised model:

- Every `Observation` field is a copy of a field that file already defines.
  `Mechanics`, `Base`, `Severity`, `Undetermined`, and `UndeterminedChecks` come
  from `Report`; `At` is `Report.ScannedAt`; `Asset` is `Report.Asset`.
- The capability bits are exactly the mechanics the `CapabilityCheck` uses to set
  base severity (`auth_required`, `auth_revocable`, `auth_clawback_enabled`).
  Nothing this document calls a capability is derived from a check that is not
  capability.
- The reported-only bits are exactly the mechanics produced by the `reputation`
  and `sep1-domain` checks, which the aggregation in that file already keeps out
  of base severity and confines to escalation. Attribution here follows the same
  split: reputation moves `severity`, never `base_severity`, and is attributed
  accordingly.
- `Undetermined` is read as the file uses it — one unreachable source makes the
  observation partial — so an outage neither fabricates an addition nor hides
  one.

No new severity semantics are introduced. The comparison only subtracts one
already-classified report from another.

## What this does not do

- **No detection pipeline.** Nothing schedules scans, diffs a feed, or alerts.
  The comparison functions are pure and someone has to call them with two
  observations.
- **No storage.** No history is written anywhere. Where observations come from,
  and how they are retained, is not decided here beyond the observation-versus-
  transition split above.
- **No API or CLI surface.** The types carry JSON tags so a future endpoint or
  command has a shape to render, but nothing exposes them yet.

## Out of scope

Do not implement detection here. Do not build storage here.

## Tests

- No automated test in the design issues; the comparison functions themselves
  are tested where they live:
  `go test ./internal/temporal/ -run Addition -v`,
  `go test ./internal/temporal/ -run Removal -v`,
  `go test ./internal/temporal/ -run Severity -v`.

## Verification

```sh
go test ./internal/temporal/ -v
```

Design document reviewed against `internal/mechanics/mechanics.go`.
