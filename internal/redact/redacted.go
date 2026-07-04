// Package redact implements RanA's non-optional secrets-redaction pipeline
// (docs/REDACTION.md). It is part of the trust core and held to the
// strictest testing bar (CLAUDE.md §3.1).
//
// The load-bearing idea lives in this file: Redacted is the ONLY string type
// the ledger writer accepts. Captured strings become Redacted exclusively by
// passing through a Pipeline, so a raw string cannot reach a leaf hash by
// construction — from any process (invariant 7, CLAUDE.md §6).
package redact

// Redacted is a string that has passed the redaction pipeline (or was declared
// a compile-time program constant via Literal). The ledger writer and the
// canonical event encoder accept string data only as this type.
type Redacted string

// Literal marks a program constant — a rule identifier, an enum label, a
// well-known static path — as safe without passing the pipeline.
//
// It must ONLY be called with compile-time constant strings. Passing captured
// data (argv, paths, marker fields, anything that originated outside the
// binary) through Literal is a P3 violation; reviews and CI treat any call
// site with a non-constant argument as a build-blocking defect.
func Literal(s string) Redacted { return Redacted(s) }
