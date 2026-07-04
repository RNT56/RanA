package collector

import "strings"

// Exe-provenance enrichment (Tier-2): additive Data fields on proc.exec —
// exe_first_seen, exe_changed, exe_known — computed entirely from
// information already available in-process (a caller-supplied file digest
// plus a small embedded allowlist). No env read (P3), no network call
// (D24), no new EventType (schema is frozen; these are additive attrs on
// the existing proc.exec event per CONTRACTS).
//
// P1 (kernel truth over agent self-report): the digest itself must
// originate from a kernel-truth-adjacent computation the caller performs
// (a userspace hash of the exe's on-disk bytes, keyed by the kernel-vended
// ExePath) — this package does not trust anything about *what* the digest
// is, it only tracks pairings it is told about. Nothing here is required
// to reconstruct the record; if the caller never supplies a digest, the
// event is a perfectly complete proc.exec without exe_first_seen/
// exe_changed/exe_known (P1: enrichment is additive, never load-bearing).

// exeSeen is one session's exe-provenance memory: which (path,digest)
// pairs have been observed, and the most recent digest seen for each path
// (to detect a swap even when the new digest is itself known from a
// different path).
type exeSeen struct {
	pairs        map[string]map[[32]byte]bool // exePath -> set of digests ever seen
	lastDigest   map[string][32]byte          // exePath -> most recently seen digest
	hasLastKnown map[string]bool              // exePath -> lastDigest is populated
}

func newExeSeen() *exeSeen {
	return &exeSeen{
		pairs:        make(map[string]map[[32]byte]bool),
		lastDigest:   make(map[string][32]byte),
		hasLastKnown: make(map[string]bool),
	}
}

// observe records one (exePath, digest) sighting and reports:
//   - firstSeen: this exact (exePath, digest) pair was never seen before
//     in this session.
//   - changed: exePath was previously seen in this session with a
//     DIFFERENT digest than the one supplied now (a swapped binary at a
//     stable path — the signal D9-adjacent tooling cares about).
func (s *exeSeen) observe(exePath string, digest [32]byte) (firstSeen, changed bool) {
	digestSet, ok := s.pairs[exePath]
	if !ok {
		digestSet = make(map[[32]byte]bool)
		s.pairs[exePath] = digestSet
	}
	firstSeen = !digestSet[digest]
	digestSet[digest] = true

	if s.hasLastKnown[exePath] && s.lastDigest[exePath] != digest {
		changed = true
	}
	s.lastDigest[exePath] = digest
	s.hasLastKnown[exePath] = true

	return firstSeen, changed
}

// exeSeenFor returns (creating if necessary) the per-session exeSeen
// tracker. Callers MUST hold e.mu.
func (e *Enricher) exeSeenFor(session string) *exeSeen {
	if e.exeProvenance == nil {
		e.exeProvenance = make(map[string]*exeSeen)
	}
	s, ok := e.exeProvenance[session]
	if !ok {
		s = newExeSeen()
		e.exeProvenance[session] = s
	}
	return s
}

// Classification labels for the exe_known Data field. These are fixed,
// non-secret enum-shaped strings (never derived from captured data), kept
// as constants so callers and tests never hand-type the label.
const (
	// ExeKnownAllowlisted means exePath's basename matches a common
	// interpreter/shell binary at one of its conventional install
	// directories (see knownGoodExePaths below) — purely a local,
	// embedded classification, never a network reputation lookup (D24).
	ExeKnownAllowlisted = "allowlisted"
	// ExeKnownUnclassified means exePath did not match the embedded
	// allowlist. This is NOT a verdict of maliciousness — the overwhelming
	// majority of exec'd binaries in any agent session are unclassified
	// and completely benign (a project's own build output, a language's
	// package-manager-installed tool, etc). It only means "not a common
	// interpreter/shell at a conventional path".
	ExeKnownUnclassified = "unclassified"
)

// knownGoodExeDirs are the conventional install directories RanA checks
// when classifying an executable path (D24: local/embedded only, never a
// network reputation service). Deliberately small and boring — this is
// not a malware-detection allowlist, just "is this the shell/interpreter
// you'd expect to find here", which is the cheap, deterministic, always-
// available signal a human reviewing a timeline finds useful context for
// (an exec of `/bin/bash` reads very differently from an exec of a
// same-named binary dropped in a scratch directory).
var knownGoodExeDirs = []string{
	"/bin/",
	"/usr/bin/",
	"/usr/local/bin/",
	"/sbin/",
	"/usr/sbin/",
}

// knownGoodExeBasenames are common interpreter/shell binary basenames.
// Version-suffixed basenames (python3.11, node18, ...) are matched by
// prefix in ClassifyExePath, not enumerated here individually.
var knownGoodExeBasenames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "fish": true,
	"env":    true,
	"python": true, "python3": true, "python2": true,
	"perl": true, "ruby": true, "node": true, "nodejs": true,
	"awk": true, "gawk": true, "sed": true,
}

// knownGoodBasenamePrefixes covers version-suffixed interpreter names
// (python3.11, node18, ruby3.2) without enumerating every version string.
var knownGoodBasenamePrefixes = []string{"python3.", "python2.", "node", "ruby"}

// ClassifyExePath returns ExeKnownAllowlisted iff path's basename matches a
// common interpreter/shell name AND path's directory is one of the
// conventional install locations in knownGoodExeDirs — matching only the
// basename would let a binary named "bash" dropped in an arbitrary
// directory (e.g. by a compromised agent staging a fake shell) claim the
// allowlisted label, which would defeat the entire point of the signal.
// Purely local/embedded (D24); never a network call.
func ClassifyExePath(path string) string {
	if path == "" {
		return ExeKnownUnclassified
	}

	dir, base := splitDirBase(path)
	if base == "" {
		return ExeKnownUnclassified
	}

	inKnownDir := false
	for _, d := range knownGoodExeDirs {
		if dir == d {
			inKnownDir = true
			break
		}
	}
	if !inKnownDir {
		return ExeKnownUnclassified
	}

	if knownGoodExeBasenames[base] {
		return ExeKnownAllowlisted
	}
	for _, prefix := range knownGoodBasenamePrefixes {
		if strings.HasPrefix(base, prefix) {
			return ExeKnownAllowlisted
		}
	}
	return ExeKnownUnclassified
}

// splitDirBase splits an absolute path into its directory (with trailing
// slash, e.g. "/usr/bin/") and basename. A path with no '/' or an empty
// basename (trailing slash) yields ("", "").
func splitDirBase(path string) (dir, base string) {
	idx := strings.LastIndexByte(path, '/')
	if idx < 0 {
		return "", ""
	}
	dir = path[:idx+1]
	base = path[idx+1:]
	return dir, base
}
