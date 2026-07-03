package redact

import (
	"fmt"
	"regexp"
	"strings"
)

// markerPattern matches a complete typed-replacement marker
// (⟦R:<class>:<lenclass>:<crc>⟧, docs/REDACTION.md §4). Any structural or
// entropy match whose captured span IS a marker (in full) is left alone:
// otherwise a generic pattern like "password=<value>" would re-wrap an
// already-redacted marker on a second pass (the marker text itself looks
// like a plausible high-entropy/credential-shaped value), breaking
// idempotency and burning through the salted-CRC budget for no reason.
var markerPattern = regexp.MustCompile(`^⟦R:[a-z]+:[smlx]+:[0-9a-f]{4}⟧$`)

// markerPatternGlobal is the unanchored form of markerPattern, used to find
// every already-present marker span inside an arbitrary string so it can be
// excluded wholesale from re-matching. This is what makes Redact idempotent
// even when a marker sits directly adjacent to non-delimiter runes (no
// whitespace boundary) that would otherwise let the entropy tokenizer's
// token span straddle across the marker's own ':' separators and mangle it
// on a second pass.
var markerPatternGlobal = regexp.MustCompile(`⟦R:[a-z]+:[smlx]+:[0-9a-f]{4}⟧`)

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

// RedactArgv redacts each element of argv independently, matching how a
// kernel-captured argv vector arrives (per-element, no cross-element
// joining of a secret split across an argv boundary).
func (p *Pipeline) RedactArgv(argv []string) []Redacted {
	out := make([]Redacted, len(argv))
	for i, a := range argv {
		out[i] = p.Redact(a)
	}
	return out
}

// RedactPath redacts a filesystem path per-segment, per docs/REDACTION.md
// Stage 3: each path component is evaluated as its own candidate token
// against the entropy thresholds, with a contextual allowlist for
// known-benign high-entropy shapes (git object paths, content-addressed
// store paths under a directory named "objects" or "commits", and
// version-4-shaped UUIDs). Non-entropy structural patterns (e.g. an AWS key
// embedded in a segment) still apply per segment.
func (p *Pipeline) RedactPath(pth string) Redacted {
	// Preserve a leading slash / scheme-less separators exactly; split on
	// "/" only (paths, not URLs — those go through Redact/argv instead).
	segments := strings.Split(pth, "/")
	segClasses := classifyPathContext(segments)

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
// contextually allowlisted from the entropy pass: a 40- or 64-hex segment
// under ".git/objects" (the classic two-char/rest split, matched on the
// full remainder) or under a directory literally named "objects" or
// "commits", or a version-4-shaped UUID segment anywhere.
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
			// "commits" contextually allowlists a hex blob under it.
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

// isUUIDv4Shape reports whether s has the canonical
// 8-4-4-4-12 hyphenated hex UUID shape (version nibble not enforced beyond
// the standard grouping, since kernel/path sources commonly present
// UUIDv1/v4/v5 alike and the allowlist is about shape, not strict RFC 4122
// version compliance).
func isUUIDv4Shape(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
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
	isDelim := func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '=' || r == ':' || r == '/'
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
		// extension glued on, "<40-hex>.dat", whose combined alphabet
		// dilutes Shannon entropy below the bar and whose non-hex suffix
		// breaks the whole-token hex/base64 shape check; or two independent
		// blobs joined by a non-delimiter separator like '!'). Fall back to
		// scanning for every embedded hex/base64 run of length >= 32 within
		// the token and flag each one — this is what makes
		// docs/REDACTION.md's separate "base64/hex blobs >= 32" clause
		// actually fire on blobs embedded in a larger token, not only on
		// tokens that are purely a blob and nothing else, and catches every
		// such blob rather than only the single longest one.
		for _, run := range hexOrBase64Runs(tok, 32) {
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

// marker builds the typed-replacement string ⟦R:<class>:<lenclass>:<crc>⟧
// for a redacted value, per docs/REDACTION.md §4.
func (p *Pipeline) marker(value, class string) string {
	return fmt.Sprintf("⟦R:%s:%s:%04x⟧", class, lenClass(len(value)), crc16CCITTFalse(value, p.salt))
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

// crc16CCITTFalse computes CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no
// reflect, no xorout) over value‖salt, per docs/REDACTION.md §4.
func crc16CCITTFalse(value string, salt []byte) uint16 {
	var crc uint16 = 0xFFFF
	update := func(b byte) {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	for i := 0; i < len(value); i++ {
		update(value[i])
	}
	for _, b := range salt {
		update(b)
	}
	return crc
}
