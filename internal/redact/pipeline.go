package redact

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"

	"lukechampine.com/blake3"
)

// markerPattern matches a complete typed-replacement marker
// (⟦R:<class>:<lenclass>:<crc>⟧, docs/REDACTION.md §4). Any structural or
// entropy match whose captured span IS a marker (in full) is left alone:
// otherwise a generic pattern like "password=<value>" would re-wrap an
// already-redacted marker on a second pass (the marker text itself looks
// like a plausible high-entropy/credential-shaped value), breaking
// idempotency and burning through the salted-CRC budget for no reason.
var markerPattern = regexp.MustCompile(`^⟦R:[a-z]+:[smlx]+:[0-9a-f]{8}⟧$`)

// markerPatternGlobal is the unanchored form of markerPattern, used to find
// every already-present marker span inside an arbitrary string so it can be
// excluded wholesale from re-matching. This is what makes Redact idempotent
// even when a marker sits directly adjacent to non-delimiter runes (no
// whitespace boundary) that would otherwise let the entropy tokenizer's
// token span straddle across the marker's own ':' separators and mangle it
// on a second pass.
var markerPatternGlobal = regexp.MustCompile(`⟦R:[a-z]+:[smlx]+:[0-9a-f]{8}⟧`)

// Pipeline is a compiled, salted redaction pipeline (docs/REDACTION.md
// Stages 2-4). A Pipeline is safe for concurrent use by multiple goroutines
// after construction: all fields are immutable post-NewPipeline.
type Pipeline struct {
	salt        []byte
	patterns    []pattern
	minLen      int
	bitsPerChar float64
}

// NewPipeline compiles a Pipeline with the given per-ledger salt (used to
// key the typed-replacement CRC, docs/REDACTION.md §4) and options. The
// salt must be non-empty. Options are applied in order; WithExtraPatterns
// appends to the built-in set, WithStricterEntropy may only tighten the
// default Stage 3 thresholds.
func NewPipeline(salt []byte, opts ...Option) (*Pipeline, error) {
	if len(salt) == 0 {
		return nil, ErrEmptySalt
	}
	saltCopy := make([]byte, len(salt))
	copy(saltCopy, salt)

	built := builtinPatterns()
	patCopy := make([]pattern, len(built))
	copy(patCopy, built)

	p := &Pipeline{
		salt:        saltCopy,
		patterns:    patCopy,
		minLen:      defaultMinLen,
		bitsPerChar: defaultBitsPerChar,
	}
	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// span is a half-open [start,end) byte range of raw matched against a
// structural or entropy rule, tagged with the class that produced it.
type span struct {
	start, end int
	class      string
	// structural is true for Stage 2 matches; false for Stage 3 (entropy)
	// matches. Structural spans win overlap resolution over entropy spans
	// per docs/REDACTION.md: "structural class wins over entropy".
	structural bool
}

// Redact runs Stages 2-4 of docs/REDACTION.md over raw and returns the
// result as a Redacted value. Redact is idempotent: redacting its own
// output is a no-op, because typed-replacement markers do not themselves
// match any structural or entropy rule.
func (p *Pipeline) Redact(raw string) Redacted {
	existingMarkers := findMarkerSpans(raw)

	spans := p.structuralSpans(raw)
	spans = filterOverlapping(spans, existingMarkers)
	entropy := p.entropySpans(raw, append(append([]span{}, spans...), existingMarkers...))
	spans = append(spans, entropy...)
	spans = resolveOverlaps(append(spans, existingMarkers...))
	spans = dropMarkerPlaceholders(spans)
	return Redacted(p.applySpans(raw, spans))
}

// findMarkerSpans returns the byte spans of every already-present typed-
// replacement marker in s, treated as pre-claimed and left untouched by any
// later stage (see markerPatternGlobal doc comment).
func findMarkerSpans(s string) []span {
	locs := markerPatternGlobal.FindAllStringIndex(s, -1)
	out := make([]span, 0, len(locs))
	for _, loc := range locs {
		out = append(out, span{start: loc[0], end: loc[1], class: "", structural: true})
	}
	return out
}

// dropMarkerPlaceholders removes the pre-claimed marker placeholder spans
// (see findMarkerSpans) after they've done their job of winning overlap
// resolution — applySpans must never try to re-emit a marker for text that
// is already a marker.
func dropMarkerPlaceholders(spans []span) []span {
	out := spans[:0:0]
	for _, sp := range spans {
		if sp.class == "" {
			continue
		}
		out = append(out, sp)
	}
	return out
}

// filterOverlapping drops any span in spans that overlaps any span in
// against.
func filterOverlapping(spans, against []span) []span {
	if len(against) == 0 {
		return spans
	}
	out := spans[:0:0]
	for _, sp := range spans {
		overlap := false
		for _, a := range against {
			if sp.start < a.end && a.start < sp.end {
				overlap = true
				break
			}
		}
		if !overlap {
			out = append(out, sp)
		}
	}
	return out
}

// credentialFlagRe matches an argv element that is a bare credential-bearing
// flag (long form, no attached "=value"): the value is then in the FOLLOWING
// element, where no in-string keyword is visible to the entropy/structural
// passes. Single-char short flags (-p) are deliberately excluded — they are
// too ambiguous (a port, a pattern) to redact their operand safely, so a
// short-flag-split credential is a documented residual.
var credentialFlagRe = regexp.MustCompile(`(?i)^--?(?:password|passwd|pwd|passphrase|passcode|secret|secret-?key|client-?secret|private-?key|token|api-?key|apikey|access-?key|access-?token|auth-?token|auth-?key|bearer-?token|credentials?|pin|otp)$`)

// RedactArgv redacts a kernel-captured argv vector. Each element is redacted
// on its own (a secret is usually self-contained in one element), with ONE
// cross-element rule: when an element is a bare credential flag (e.g.
// "--password"), the NEXT element is its value and is redacted wholesale —
// otherwise a secret split as ["--password", "s3cr3t"] leaks, because the
// keyword the structural/entropy passes rely on lives in the previous element.
func (p *Pipeline) RedactArgv(argv []string) []Redacted {
	out := make([]Redacted, len(argv))
	for i, a := range argv {
		if i > 0 && a != "" && !markerPattern.MatchString(a) &&
			!strings.HasPrefix(a, "-") && credentialFlagRe.MatchString(argv[i-1]) {
			// Operand of a credential flag: the whole element is the secret.
			out[i] = Redacted(p.marker(a, classEntropy))
			continue
		}
		out[i] = p.Redact(a)
	}
	return out
}

// PathTrust is the provenance of a path handed to RedactPath, which decides
// whether the content-addressed allowlist may apply. It is the kernel-truth
// discriminator (P1) that resolves the precision/leak tension in that
// allowlist (see classifyPathContext).
type PathTrust uint8

const (
	// PathClaimed is the SAFE DEFAULT (zero value): the path is
	// agent-influenced — a syscall-argument-derived / TOCTOU-racy path
	// (path_source=claimed), or one whose provenance is simply unknown. The
	// content-addressed allowlist is NOT applied, so a segment an attacker
	// CRAFTS to look like a content hash (…/objects/<hex-secret>) or a v4 UUID
	// is entropy-scanned and redacted like anything else.
	PathClaimed PathTrust = iota
	// PathResolved: the path came from the kernel's in-BPF dentry+mount walk
	// (path_source=resolved) — the file genuinely exists at this path. The
	// content-addressed allowlist applies, so a real git/nix content hash is
	// not over-redacted. An attacker cannot forge a resolved path without
	// actually creating the file, at which point a hex-encoded secret in the
	// filename is a covert channel outside redaction's threat model (LIMITS.md).
	PathResolved
)

// RedactPath redacts a filesystem path per-segment, per docs/REDACTION.md
// Stage 3: each path component is evaluated as its own candidate token against
// the entropy thresholds. For a kernel-RESOLVED path (trust == PathResolved) a
// contextual allowlist spares known-benign high-entropy shapes (content hashes
// under an "objects"/"commits" directory, RFC-4122 v4 UUIDs) so the path a
// file event exists to record is not shredded. For a CLAIMED path (the safe
// default) that allowlist is disabled — an agent-controlled segment shaped
// like a content hash is redacted, closing the crafted-path blind spot.
// Non-entropy structural patterns (e.g. an AWS key embedded in a segment)
// always apply per segment, regardless of trust.
func (p *Pipeline) RedactPath(pth string, trust PathTrust) Redacted {
	// Preserve a leading slash / scheme-less separators exactly; split on
	// "/" only (paths, not URLs — those go through Redact/argv instead).
	segments := strings.Split(pth, "/")
	// The content-addressed allowlist is trusted only for kernel-resolved
	// paths; a claimed path gets no allowlist, so every segment is scanned.
	var segClasses map[int]bool
	if trust == PathResolved {
		segClasses = classifyPathContext(segments)
	} else {
		segClasses = map[int]bool{}
	}

	out := make([]string, len(segments))
	for i, seg := range segments {
		if seg == "" {
			out[i] = seg
			continue
		}
		if segClasses[i] {
			// Contextually allowlisted: still run structural patterns
			// (a literal AWS key sitting in a git-objects-shaped segment
			// is not realistic, but Stage 2 is cheap and unconditional
			// everywhere else, so apply it here too for consistency)
			// EXCEPT the entropy pass, which is what the allowlist exists
			// to suppress.
			spans := p.structuralSpans(seg)
			spans = resolveOverlaps(spans)
			out[i] = p.applySpans(seg, spans)
			continue
		}
		out[i] = string(p.Redact(seg))
	}
	return Redacted(strings.Join(out, "/"))
}

// classifyPathContext returns, per segment index, whether that segment is
// contextually allowlisted from the entropy pass: a hash-length hex segment
// under a directory named "objects" or "commits" (git, nix, ostree and other
// content-addressed stores — extremely common in agent workspaces, where
// redacting every content hash would destroy the forensic value of the path),
// or a strict RFC-4122 version-4 UUID segment anywhere.
//
// This allowlist is applied ONLY to kernel-resolved paths (see RedactPath /
// PathTrust): the caller vouches, from the kernel dentry walk, that the file
// genuinely exists at this path, so a hash-shaped segment is a real content
// hash and must not be shredded. On a CLAIMED (agent-influenced) path the
// allowlist is not consulted at all, so a secret an attacker crafts into a
// hash-shaped or UUID-shaped segment is redacted. The only residual is a
// malicious agent that CREATES a real file whose name hex-encodes a secret and
// then touches it — a covert channel out of redaction's threat model
// (LIMITS.md §"redaction"; a fully-malicious agent has far easier exfil).
// Structural provider patterns (Stage 2) still run on allowlisted segments, so
// a literal AKIA…/sk-… secret embedded in such a segment is still caught.
func classifyPathContext(segments []string) map[int]bool {
	allow := make(map[int]bool)
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if isUUIDv4Shape(seg) {
			allow[i] = true
			continue
		}
		if isHexString(seg) && (len(seg) == 38 || len(seg) == 40 || len(seg) == 62 || len(seg) == 64) {
			// git objects layout: .../objects/<2-hex>/<38-hex remainder>
			if i >= 2 && segments[i-1] != "" && isHexString(segments[i-1]) && len(segments[i-1]) == 2 && (segments[i-2] == "objects") {
				allow[i] = true
				continue
			}
			// generic: any ancestor directory literally named "objects" or
			// "commits" contextually allowlists a hash-length hex blob under it.
			for j := i - 1; j >= 0; j-- {
				if segments[j] == "objects" || segments[j] == "commits" {
					allow[i] = true
					break
				}
			}
		}
	}
	return allow
}

// isUUIDv4Shape reports whether s is a canonical RFC-4122 version-4 UUID:
// the 8-4-4-4-12 hyphenated hex grouping AND the version nibble (first char of
// the 3rd group) == '4' AND the variant nibble (first char of the 4th group)
// in {8,9,a,b}. Enforcing the version/variant nibbles (not just the grouping)
// shrinks the allowlist's blind spot ~64x: a random secret shaped like a UUID
// now has only a ~1/64 chance of also carrying valid v4 nibbles. A non-v4
// UUID (v1/v5) is not allowlisted, but is not over-redacted either — with '-'
// not a token delimiter it stays one token whose Shannon entropy is below the
// bar, so it passes through untouched.
func isUUIDv4Shape(s string) bool {
	if len(s) != 36 {
		return false
	}
	isHex := func(c byte) bool {
		return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHex(s[i]) {
				return false
			}
		}
	}
	// Version nibble (index 14) must be '4'.
	if s[14] != '4' {
		return false
	}
	// Variant nibble (index 19) must be one of 8, 9, a/A, b/B.
	switch s[19] {
	case '8', '9', 'a', 'b', 'A', 'B':
	default:
		return false
	}
	return true
}

// structuralSpans runs the compiled Stage 2 pattern set over s and returns
// every match span, honoring each pattern's target group.
func (p *Pipeline) structuralSpans(s string) []span {
	var out []span
	for _, pat := range p.patterns {
		locs := pat.re.FindAllStringSubmatchIndex(s, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			if pat.group > 0 && pat.group*2+1 < len(loc) && loc[pat.group*2] >= 0 {
				start, end = loc[pat.group*2], loc[pat.group*2+1]
			}
			if start == end {
				continue
			}
			if markerPattern.MatchString(s[start:end]) {
				continue
			}
			if pat.validate != nil && !pat.validate(s[start:end]) {
				continue
			}
			out = append(out, span{start: start, end: end, class: pat.class, structural: true})
		}
	}
	return out
}

// entropySpans runs Stage 3 over s, skipping any byte range already covered
// by a structural (Stage 2) span (structural class wins over entropy on
// overlap, and there is no reason to entropy-scan text already claimed).
// Tokens are split on whitespace and '=' and ':' delimiters per
// docs/REDACTION.md Stage 3 ("A token (whitespace/=/:-delimited)"), plus
// '/' — the same spec section states "Paths are not exempt — they are
// evaluated per segment", i.e. a '/'-delimited path component is itself a
// candidate token; treating '/' as a general delimiter (not just inside
// RedactPath) is what keeps ordinary path-shaped strings that pass through
// plain Redact (e.g. in argv or free-text fields) from being entropy-scanned
// as one giant multi-segment token and false-positiving on their combined
// character diversity.
func (p *Pipeline) entropySpans(s string, existing []span) []span {
	var out []span
	// Token delimiters. Beyond whitespace/=/:/ (the documented base set), '.'
	// ',' ';' '@' '|' are delimiters too. This is load-bearing in BOTH
	// directions: it stops a dotted FQDN ("svc.prod.example.com") from being
	// scored as ONE high-diversity token and over-redacted whole (which would
	// destroy the hostname a net.dns/net.connect event exists to record), and
	// it stops a real secret glued to a benign label by '.'/','/'@' from
	// having its per-char entropy diluted below the bar and leaking. None of
	// these characters is in the hex/base64 alphabet, so splitting on them
	// never fractures a hex/base64 secret; structural secrets that legitimately
	// contain them (JWTs, connection strings) are matched in Stage 2 first and
	// excluded from this pass.
	isDelim := func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '=', ':', '/', '.', ',', ';', '@', '|':
			return true
		}
		return false
	}
	start := -1
	flush := func(end int) {
		if start < 0 {
			return
		}
		tok := s[start:end]
		if markerPattern.MatchString(tok) {
			start = -1
			return
		}
		if isHighEntropyToken(tok, p.minLen, p.bitsPerChar) && !coveredByStructural(start, end, existing) {
			out = append(out, span{start: start, end: end, class: classEntropy, structural: false})
			start = -1
			return
		}
		// The whole token didn't qualify (e.g. a hex digest with a file
		// extension glued on via a non-delimiter separator like '!', whose
		// combined alphabet dilutes Shannon entropy below the bar and whose
		// non-hex suffix breaks the whole-token shape check; or two independent
		// blobs joined by such a separator). Fall back to scanning for every
		// embedded high-entropy hex/base64 run within the token and flag each
		// one — this is what makes docs/REDACTION.md's separate "base64/hex
		// blobs" clause fire on blobs embedded in a larger token, not only on
		// tokens that are purely a blob and nothing else, and catches every
		// such blob rather than only the single longest one.
		for _, run := range highEntropyRuns(tok) {
			runText := tok[run[0]:run[1]]
			if isDictionaryWord(runText) || isUUIDv4Shape(runText) {
				continue
			}
			subStart, subEnd := start+run[0], start+run[1]
			if !coveredByStructural(subStart, subEnd, existing) {
				out = append(out, span{start: subStart, end: subEnd, class: classEntropy, structural: false})
			}
		}
		start = -1
	}
	for i, r := range s {
		if isDelim(r) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(s))
	return out
}

func coveredByStructural(start, end int, existing []span) bool {
	for _, e := range existing {
		if !e.structural {
			continue
		}
		if start < e.end && e.start < end {
			return true
		}
	}
	return false
}

// resolveOverlaps applies "leftmost-longest; structural class wins over
// entropy" (docs/REDACTION.md Stage 2/3 overlap rule) and returns a
// non-overlapping, start-sorted span list.
func resolveOverlaps(spans []span) []span {
	if len(spans) == 0 {
		return spans
	}
	// Sort by start asc, then by (structural first, longer first) so the
	// greedy sweep below picks the highest-priority span at each position.
	sorted := make([]span, len(spans))
	copy(sorted, spans)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && spanLess(sorted[j], sorted[j-1]); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	var out []span
	lastEnd := -1
	for _, sp := range sorted {
		if sp.start < lastEnd {
			continue // overlaps a higher-priority already-chosen span
		}
		out = append(out, sp)
		lastEnd = sp.end
	}
	return out
}

func spanLess(a, b span) bool {
	if a.start != b.start {
		return a.start < b.start
	}
	if a.structural != b.structural {
		return a.structural // structural sorts first
	}
	// longer span first (leftmost-longest)
	return (a.end - a.start) > (b.end - b.start)
}

// applySpans replaces each span in s with its typed-replacement marker
// (docs/REDACTION.md §4), left to right, leaving everything outside a span
// untouched.
func (p *Pipeline) applySpans(s string, spans []span) string {
	if len(spans) == 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, sp := range spans {
		if sp.start < prev {
			continue
		}
		b.WriteString(s[prev:sp.start])
		b.WriteString(p.marker(s[sp.start:sp.end], sp.class))
		prev = sp.end
	}
	b.WriteString(s[prev:])
	return b.String()
}

// marker builds the typed-replacement string ⟦R:<class>:<lenclass>:<checksum>⟧
// for a redacted value, per docs/REDACTION.md §4.
func (p *Pipeline) marker(value, class string) string {
	return fmt.Sprintf("⟦R:%s:%s:%08x⟧", class, lenClass(len(value)), markerChecksum(value, p.salt))
}

// lenClass buckets a redacted span's length into s/m/l/xl so the exact
// length (itself potentially identifying) never appears in the marker.
func lenClass(n int) string {
	switch {
	case n <= 20:
		return "s"
	case n <= 40:
		return "m"
	case n <= 80:
		return "l"
	default:
		return "xl"
	}
}

// markerChecksum is the salted correlation checksum embedded in a marker: the
// low 32 bits of BLAKE3(value ‖ salt).
//
// It replaced a CRC-16/CCITT-FALSE over the same input. That change fixes two
// audit findings at once (docs/REDACTION.md §4):
//
//   - A CRC is GF(2)-AFFINE in every input bit, including the salt's, so each
//     marker leaked one linear equation over the salt bits; with enough
//     known-plaintext markers the per-ledger salt was recoverable by Gaussian
//     elimination. BLAKE3 is a cryptographic hash — not affine — so the salt
//     cannot be recovered by linear algebra, and a marker is a genuine one-way
//     tag over its value.
//   - The old checksum was 16 bits, so two different secrets of the same
//     class/length collided into an identical marker at ~1/65536 — frequent
//     enough in a busy ledger to produce a FALSE "same secret was reused here
//     and here" inference. 32 bits drops that to ~1/4e9, so the correlation
//     hint the marker provides is reliable.
//
// A nil/empty salt is rejected at the Pipeline level (ErrEmptySalt); this
// function itself is total and never panics on a nil salt.
func markerChecksum(value string, salt []byte) uint32 {
	h := blake3.New(32, nil)
	_, _ = h.Write([]byte(value))
	_, _ = h.Write(salt)
	sum := h.Sum(nil)
	return binary.BigEndian.Uint32(sum[:4])
}
