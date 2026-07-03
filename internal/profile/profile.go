// Package profile implements RanA's profile engine (docs/PROFILES.md, plan
// D9/D17): parsing and validating the TOML packs that tell RanA how to
// recognize an agent, what to content-digest, which extra paths are
// sensitive, how markers enrich causality, and how the timeline should
// read.
//
// Profiles can only make RanA stricter or richer, never blinder
// (docs/PROFILES.md): they may add sensitive paths, add redaction patterns,
// tighten entropy thresholds, and scope digests, but they cannot remove a
// built-in, loosen redaction, or disable a capture class below the D7
// baseline. Load and Parse enforce this at parse time (validate.go) with
// named errors.
package profile

import "fmt"

// MatchRule holds the auto-detection rules for a profile (docs/PROFILES.md
// [match]). Matching is a convenience only — attribution is always the
// cgroup, never the exe/argv heuristic. See the package-level Match
// function for how these rules are evaluated against a live process.
type MatchRule struct {
	Auto         bool
	ExeBasename  []string
	ArgvContains []string
}

// Capture holds the per-event-class capture booleans (docs/PROFILES.md
// [capture]). In v1 every shipped profile keeps the full D7 set on;
// exec/network_connect/sensitive-read can never be disabled by any profile
// (enforced in validate.go).
type Capture struct {
	Exec           bool
	ForkExit       bool
	FileWrite      bool
	FileMetaOps    bool
	NetworkConnect bool
	NetworkFlow    bool
	UnixSockets    bool
}

// Digest holds content-digest scoping (docs/PROFILES.md [digest]).
// $SESSION_CWD is expanded by ExpandSessionCWD at session-start time, not
// at parse time (the session's working directory is not known yet).
type Digest struct {
	Scopes  []string
	Exclude []string
}

// SensitiveRead holds profile-added entries appended to the built-in
// in-kernel sensitive-path watchlist (docs/PROFILES.md [sensitive_read]).
// Additive only: the built-ins (BuiltinSensitivePaths) always apply and
// cannot be removed by a profile.
type SensitiveRead struct {
	Extra []string
}

// Redaction holds optional profile-supplied redaction tightening
// (docs/PROFILES.md [redaction]). ExtraPatterns are additive; the entropy
// fields may only be set stricter than docs/REDACTION.md's defaults
// (enforced in validate.go). Zero values mean "not set" (EntropyMinLen == 0
// and EntropyThreshold == 0 are not valid thresholds and are treated as
// "unset" by validateEntropy in validate.go — no consumer package in this
// repo yet turns a Profile into redact.Options; a future wiring point
// (internal/collector or internal/service) must replicate this same
// both-zero sentinel when constructing the runtime redact.Pipeline from a
// loaded Profile).
type Redaction struct {
	ExtraPatterns    []string
	EntropyMinLen    int
	EntropyThreshold float64
}

// Markers holds the optional first-party enrichment channel configuration
// (docs/PROFILES.md [markers], P7). CarryFields is an allowlist and
// ForbidFields a belt-and-suspenders denylist; nothing outside CarryFields
// ever reaches the ledger regardless of what ForbidFields says.
type Markers struct {
	Enabled      bool
	Socket       string
	Events       []string
	CarryFields  []string
	ForbidFields []string
}

// Timeline holds UI presentation hints (docs/PROFILES.md [timeline]). These
// are display-only and never affect what is captured or retained.
type Timeline struct {
	Lens         string
	ClusterBy    string
	FallbackLens string
}

// Retention holds the gc-eligibility window (docs/PROFILES.md [retention]).
type Retention struct {
	TTLDays int64
}

// Profile is a fully parsed and validated RanA profile pack.
type Profile struct {
	Name        string
	Description string
	Version     int64

	Match         MatchRule
	Capture       Capture
	Digest        Digest
	SensitiveRead SensitiveRead
	Redaction     Redaction
	Markers       Markers
	Timeline      Timeline
	Retention     Retention

	// source names the origin of this profile for error messages (an
	// embedded pack path or a file path passed to LoadFile).
	source string
}

// Parse parses and validates src (TOML) as a profile pack. source names the
// input for error messages (a file path, or an embedded pack name) and does
// not affect parsing.
func Parse(src, source string) (*Profile, error) {
	doc, err := parseTOML(src)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", source, err)
	}

	if !doc.hasSection("profile") {
		return nil, fmt.Errorf("profile %s: %w", source, ErrMissingProfileSection)
	}
	name := doc.str("profile", "name")
	if name == "" {
		return nil, fmt.Errorf("profile %s: %w", source, ErrMissingName)
	}

	p := &Profile{
		Name:        name,
		Description: doc.str("profile", "description"),
		Version:     doc.int("profile", "version"),
		source:      source,

		Match: MatchRule{
			Auto:         doc.boolVal("match", "auto"),
			ExeBasename:  doc.strSlice("match", "exe_basename"),
			ArgvContains: doc.strSlice("match", "argv_contains"),
		},

		Capture: parseCapture(doc),

		Digest: Digest{
			Scopes:  doc.strSlice("digest", "scopes"),
			Exclude: doc.strSlice("digest", "exclude"),
		},

		SensitiveRead: SensitiveRead{
			Extra: doc.strSlice("sensitive_read", "extra"),
		},

		Redaction: Redaction{
			ExtraPatterns:    doc.strSlice("redaction", "extra_patterns"),
			EntropyMinLen:    int(doc.int("redaction", "entropy_min_len")),
			EntropyThreshold: doc.float64Val("redaction", "entropy_threshold"),
		},

		Markers: Markers{
			Enabled:      doc.boolVal("markers", "enabled"),
			Socket:       doc.str("markers", "socket"),
			Events:       doc.strSlice("markers", "events"),
			CarryFields:  doc.strSlice("markers", "carry_fields"),
			ForbidFields: doc.strSlice("markers", "forbid_fields"),
		},

		Timeline: Timeline{
			Lens:         doc.str("timeline", "lens"),
			ClusterBy:    doc.str("timeline", "cluster_by"),
			FallbackLens: doc.str("timeline", "fallback_lens"),
		},

		Retention: Retention{
			TTLDays: doc.int("retention", "ttl_days"),
		},
	}

	if err := validate(doc, p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", source, err)
	}

	return p, nil
}

// parseCapture reads [capture] booleans, defaulting every class to true
// (the D7 baseline, docs/PROFILES.md: "in v1 all shipped profiles keep the
// full D7 set on") when the key — or the whole [capture] table — is absent,
// so an omitted [capture] section (as in a minimal custom profile) is never
// silently narrower than the baseline.
func parseCapture(doc *tomlDoc) Capture {
	get := func(key string) bool {
		if doc.has("capture", key) {
			return doc.boolVal("capture", key)
		}
		return true
	}
	return Capture{
		Exec:           get("exec"),
		ForkExit:       get("fork_exit"),
		FileWrite:      get("file_write"),
		FileMetaOps:    get("file_meta_ops"),
		NetworkConnect: get("network_connect"),
		NetworkFlow:    get("network_flow"),
		UnixSockets:    get("unix_sockets"),
	}
}
