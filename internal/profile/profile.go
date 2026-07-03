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

// Adopt holds the lifecycle parameters `rana adopt <profile>` drives
// (docs/PROFILES.md [adopt]). It is populated only for packs that declare an
// [adopt] table — currently just openclaw.toml, the hero adopt target — and
// is nil on Profile otherwise. The profile package only models and validates
// these fields; internal/session consumes them to actually place the agent
// under a rana cgroup slice.
type Adopt struct {
	// ConfigDir is the agent's on-disk config root, used to detect an
	// existing install (openclaw: "~/.openclaw").
	ConfigDir string
	// GatewayPort is the local port the adopted daemon binds, used for a
	// liveness probe and (on macOS) host<->guest port forwarding.
	GatewayPort int64
	// LinuxSupervisor names the init system whose unit is rewritten to place
	// the daemon under rana.slice (e.g. "systemd").
	LinuxSupervisor string
	// MacOSSupervisor names the macOS supervisor for the guest-hosted daemon
	// (e.g. "launchd").
	MacOSSupervisor string
	// ConsentDefault is the default answer to the adopt-time consent prompt
	// (e.g. "yes"); the user can always decline interactively.
	ConsentDefault string
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
	Adopt         *Adopt
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
//
// Parsing uses github.com/pelletier/go-toml/v2 (a spec-complete parser):
// malformed syntax, duplicate keys, and type mismatches are rejected with a
// wrapped error rather than silently tolerated. The additive-only validation
// invariants (docs/PROFILES.md; see validate.go) are applied unchanged after
// decode.
func Parse(src, source string) (*Profile, error) {
	doc, hasProfile, err := decodeTOML(src)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", source, err)
	}

	if !hasProfile {
		return nil, fmt.Errorf("profile %s: %w", source, ErrMissingProfileSection)
	}
	name := doc.Profile.Name
	if name == "" {
		return nil, fmt.Errorf("profile %s: %w", source, ErrMissingName)
	}

	p := &Profile{
		Name:        name,
		Description: doc.Profile.Description,
		Version:     doc.Profile.Version,
		source:      source,

		Match: MatchRule{
			Auto:         doc.Match.Auto,
			ExeBasename:  doc.Match.ExeBasename,
			ArgvContains: doc.Match.ArgvContains,
		},

		Adopt: mapAdopt(doc.Adopt),

		Capture: mapCapture(doc),

		Digest: Digest{
			Scopes:  doc.Digest.Scopes,
			Exclude: doc.Digest.Exclude,
		},

		SensitiveRead: SensitiveRead{
			Extra: doc.SensitiveRead.Extra,
		},

		Redaction: Redaction{
			ExtraPatterns:    doc.Redaction.ExtraPatterns,
			EntropyMinLen:    doc.Redaction.EntropyMinLen,
			EntropyThreshold: doc.Redaction.EntropyThreshold,
		},

		Markers: Markers{
			Enabled:      doc.Markers.Enabled,
			Socket:       doc.Markers.Socket,
			Events:       doc.Markers.Events,
			CarryFields:  doc.Markers.CarryFields,
			ForbidFields: doc.Markers.ForbidFields,
		},

		Timeline: Timeline{
			Lens:         doc.Timeline.Lens,
			ClusterBy:    doc.Timeline.ClusterBy,
			FallbackLens: doc.Timeline.FallbackLens,
		},

		Retention: Retention{
			TTLDays: doc.Retention.TTLDays,
		},
	}

	if err := validate(doc, p); err != nil {
		return nil, fmt.Errorf("profile %s: %w", source, err)
	}

	return p, nil
}

// mapAdopt converts the decoded [adopt] DTO (nil when the table is absent)
// into the exported Adopt struct, preserving the nil-when-absent contract so
// packs without an [adopt] table have a nil Profile.Adopt.
func mapAdopt(a *adoptDTO) *Adopt {
	if a == nil {
		return nil
	}
	return &Adopt{
		ConfigDir:       a.ConfigDir,
		GatewayPort:     a.GatewayPort,
		LinuxSupervisor: a.LinuxSupervisor,
		MacOSSupervisor: a.MacOSSupervisor,
		ConsentDefault:  a.ConsentDefault,
	}
}

// mapCapture reads the decoded [capture] booleans, defaulting every class to
// true (the D7 baseline, docs/PROFILES.md: "in v1 all shipped profiles keep
// the full D7 set on") when the key — or the whole [capture] table — is
// absent, so an omitted [capture] section (as in a minimal custom profile)
// is never silently narrower than the baseline. Presence is carried by the
// DTO's *bool fields: nil ⇒ absent ⇒ default true.
func mapCapture(doc *decodeDoc) Capture {
	get := func(p *bool) bool {
		if p == nil {
			return true
		}
		return *p
	}
	return Capture{
		Exec:           get(doc.Capture.Exec),
		ForkExit:       get(doc.Capture.ForkExit),
		FileWrite:      get(doc.Capture.FileWrite),
		FileMetaOps:    get(doc.Capture.FileMetaOps),
		NetworkConnect: get(doc.Capture.NetworkConnect),
		NetworkFlow:    get(doc.Capture.NetworkFlow),
		UnixSockets:    get(doc.Capture.UnixSockets),
	}
}
