package profile

import (
	"github.com/pelletier/go-toml/v2"
)

// decodeDoc is the decode-target DTO for a RanA profile pack. It mirrors the
// TOML sections of docs/PROFILES.md one-for-one and is decoded by
// github.com/pelletier/go-toml/v2 (a spec-complete parser) before being
// mapped onto the exported Profile struct (profile.go). Decoding into a DTO
// rather than straight into Profile lets a few fields carry presence
// information the exported type deliberately doesn't:
//
//   - [capture] booleans are *bool so validation can distinguish "key
//     absent" (nil ⇒ defaults to the D7 baseline, all-on) from an explicit
//     "= false" (which is rejected for the frozen classes). The exported
//     Capture is plain bools with the absent-⇒-true default already applied.
//
// go-toml/v2 rejects malformed TOML, duplicate keys, and type mismatches by
// default (toml.Decoder with DisallowUnknownFields off — unknown *sections*
// like the openclaw-only [adopt] table were previously silently dropped and
// are now modeled explicitly). That strictness is the robustness win this
// parser swap buys over the previous hand-rolled subset parser.
type decodeDoc struct {
	Profile struct {
		Name        string `toml:"name"`
		Description string `toml:"description"`
		Version     int64  `toml:"version"`
	} `toml:"profile"`

	// hasProfileSection records whether a [profile] table was present at
	// all, so Parse can return ErrMissingProfileSection (an empty [profile]
	// table and an absent one both yield a zero Profile struct otherwise).
	// go-toml/v2 has no built-in "was this table present" signal, so Parse
	// re-decodes into a permissive map to answer this one question.

	Match struct {
		Auto         bool     `toml:"auto"`
		ExeBasename  []string `toml:"exe_basename"`
		ArgvContains []string `toml:"argv_contains"`
	} `toml:"match"`

	Adopt *adoptDTO `toml:"adopt"`

	Capture struct {
		Exec           *bool `toml:"exec"`
		ForkExit       *bool `toml:"fork_exit"`
		FileWrite      *bool `toml:"file_write"`
		FileMetaOps    *bool `toml:"file_meta_ops"`
		NetworkConnect *bool `toml:"network_connect"`
		NetworkFlow    *bool `toml:"network_flow"`
		UnixSockets    *bool `toml:"unix_sockets"`
	} `toml:"capture"`

	Digest struct {
		Scopes  []string `toml:"scopes"`
		Exclude []string `toml:"exclude"`
	} `toml:"digest"`

	SensitiveRead struct {
		Extra []string `toml:"extra"`
	} `toml:"sensitive_read"`

	Redaction struct {
		ExtraPatterns    []string `toml:"extra_patterns"`
		EntropyMinLen    int      `toml:"entropy_min_len"`
		EntropyThreshold float64  `toml:"entropy_threshold"`
	} `toml:"redaction"`

	Markers struct {
		Enabled      bool     `toml:"enabled"`
		Socket       string   `toml:"socket"`
		Events       []string `toml:"events"`
		CarryFields  []string `toml:"carry_fields"`
		ForbidFields []string `toml:"forbid_fields"`
	} `toml:"markers"`

	Timeline struct {
		Lens         string `toml:"lens"`
		ClusterBy    string `toml:"cluster_by"`
		FallbackLens string `toml:"fallback_lens"`
	} `toml:"timeline"`

	Retention struct {
		TTLDays int64 `toml:"ttl_days"`
	} `toml:"retention"`
}

// adoptDTO decodes the [adopt] table (currently authored only by
// openclaw.toml, docs/PROFILES.md § [adopt]). It maps directly onto the
// exported Adopt struct (profile.go).
type adoptDTO struct {
	ConfigDir       string `toml:"config_dir"`
	GatewayPort     int64  `toml:"gateway_port"`
	LinuxSupervisor string `toml:"linux_supervisor"`
	MacOSSupervisor string `toml:"macos_supervisor"`
	ConsentDefault  string `toml:"consent_default"`
}

// decodeTOML parses src (a full profile pack) with go-toml/v2 into a
// decodeDoc, and separately reports whether a top-level [profile] table was
// present (needed to return ErrMissingProfileSection rather than
// ErrMissingName for a pack that omits [profile] entirely). A malformed
// document (bad syntax, duplicate key, type mismatch, truncated input)
// returns a non-nil error — never a panic and never silent acceptance.
func decodeTOML(src string) (*decodeDoc, bool, error) {
	var doc decodeDoc
	if err := toml.Unmarshal([]byte(src), &doc); err != nil {
		return nil, false, err
	}
	// A second pass into a permissive map answers the one question the DTO
	// cannot: was [profile] declared at all? This uses the same parser, so a
	// document that unmarshaled cleanly above will unmarshal cleanly here too.
	var raw map[string]any
	if err := toml.Unmarshal([]byte(src), &raw); err != nil {
		return nil, false, err
	}
	_, hasProfile := raw["profile"]
	return &doc, hasProfile, nil
}
