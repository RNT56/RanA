package redact

import (
	"math"
	"strings"
)

// shannonEntropy returns the Shannon entropy of s in bits per character,
// computed over the byte-frequency distribution of s. Empty strings have
// zero entropy by convention.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var entropy float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// commonWords is a small, static dictionary of common English and
// technical-prose words used to suppress false positives in the entropy
// pass (e.g. "password", "configuration", "secret" as bare words with no
// value attached should not themselves be treated as high-entropy secrets).
// This is intentionally NOT exhaustive — it exists to bound benign-string
// false positives in ordinary paths and prose, not to be a full spellchecker.
var commonWords = buildCommonWords()

func buildCommonWords() map[string]struct{} {
	words := []string{
		"the", "a", "an", "and", "or", "but", "if", "then", "else", "for", "while",
		"password", "passwd", "secret", "secrets", "token", "tokens", "key", "keys",
		"configuration", "config", "settings", "options", "value", "values",
		"user", "users", "name", "names", "file", "files", "path", "paths",
		"directory", "directories", "folder", "folders", "system", "systems",
		"application", "applications", "server", "servers", "client", "clients",
		"database", "databases", "table", "tables", "column", "columns",
		"function", "functions", "method", "methods", "class", "classes",
		"object", "objects", "array", "arrays", "string", "strings",
		"number", "numbers", "boolean", "true", "false", "null", "undefined",
		"error", "errors", "warning", "warnings", "debug", "info", "trace",
		"session", "sessions", "request", "requests", "response", "responses",
		"header", "headers", "body", "bodies", "content", "contents",
		"type", "types", "format", "formats", "version", "versions",
		"install", "installed", "installing", "installation",
		"update", "updated", "updating", "updates",
		"create", "created", "creating", "creation",
		"delete", "deleted", "deleting", "deletion",
		"read", "write", "written", "writing", "readable", "writable",
		"open", "opened", "opening", "close", "closed", "closing",
		"start", "started", "starting", "stop", "stopped", "stopping",
		"linux", "windows", "darwin", "macos", "unix", "posix",
		"local", "remote", "global", "public", "private", "protected",
		"default", "defaults", "example", "examples", "sample", "samples",
		"test", "tests", "testing", "tested", "production", "development",
		"staging", "environment", "environments", "variable", "variables",
		"library", "libraries", "package", "packages", "module", "modules",
		"import", "imports", "export", "exports", "dependency", "dependencies",
		"build", "builds", "building", "compile", "compiled", "compiling",
		"binary", "binaries", "executable", "executables", "script", "scripts",
		"language", "languages", "framework", "frameworks", "runtime", "runtimes",
	}
	m := make(map[string]struct{}, len(words))
	for _, w := range words {
		m[w] = struct{}{}
	}
	return m
}

// isDictionaryWord reports whether s (case-insensitively) is a common
// English/technical word, used to suppress entropy-pass false positives on
// ordinary prose tokens.
func isDictionaryWord(s string) bool {
	if s == "" {
		return false
	}
	_, ok := commonWords[strings.ToLower(s)]
	return ok
}

// looksBase64OrHex reports whether s is entirely composed of base64
// alphabet characters (including padding) or hex digits, and is at least
// 32 characters long — the length/shape bar from docs/REDACTION.md Stage 3
// for base64/hex blobs.
func looksBase64OrHex(s string) bool {
	if len(s) < 32 {
		return false
	}
	if isHexString(s) {
		return true
	}
	return isBase64String(s)
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isBase64String(s string) bool {
	// Strip trailing '=' padding (up to 2 chars) before checking body.
	body := s
	pad := 0
	for len(body) > 0 && body[len(body)-1] == '=' && pad < 2 {
		body = body[:len(body)-1]
		pad++
	}
	if len(body) == 0 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '+' || c == '/' || c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// hexOrBase64Runs scans s for every maximal run of hex digits or base64
// alphabet characters and returns the [start,end) byte range of each one
// found that is at least minLen characters. This backs the "base64/hex
// blobs >= 32 chars" clause of docs/REDACTION.md Stage 3 for blobs embedded
// inside a larger token (e.g. a hex digest immediately followed by a file
// extension, or two independent blobs joined by a non-delimiter separator
// like '!'), where the whole-token shape check in looksBase64OrHex would
// otherwise fail because of interleaved non-blob characters. Returning
// every qualifying run (not just the longest) is what makes redaction catch
// N separate embedded secrets in one token, not only the biggest one.
func hexOrBase64Runs(s string, minLen int) [][2]int {
	isRunChar := func(c byte) bool {
		switch {
		case c >= '0' && c <= '9':
			return true
		case c >= 'a' && c <= 'z':
			return true
		case c >= 'A' && c <= 'Z':
			return true
		case c == '+' || c == '/' || c == '-' || c == '_' || c == '=':
			return true
		}
		return false
	}
	var runs [][2]int
	i := 0
	for i < len(s) {
		if !isRunChar(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isRunChar(s[j]) {
			j++
		}
		if j-i >= minLen {
			// Require the run itself to actually look hex or base64 (the
			// character class above is deliberately loose so runs like
			// "abc-def_ghi" aren't silently excluded from consideration,
			// but the final run must satisfy the real shape check).
			run := s[i:j]
			if isHexString(run) || isBase64String(run) {
				runs = append(runs, [2]int{i, j})
			}
		}
		i = j
	}
	return runs
}

// isHighEntropyToken reports whether s qualifies as a high-entropy secret
// candidate per docs/REDACTION.md Stage 3: length >= minLen, Shannon entropy
// >= bitsPerChar, and not a recognized dictionary word. Base64/hex blobs of
// length >= 32 also qualify regardless of the entropy threshold (their
// alphabet structure is itself the signal), matching the spec's separate
// "base64/hex blobs >= 32" clause.
func isHighEntropyToken(s string, minLen int, bitsPerChar float64) bool {
	if isDictionaryWord(s) {
		return false
	}
	if isUUIDv4Shape(s) {
		// Contextual allowlist per docs/REDACTION.md Stage 3 / CONTRACTS.md:
		// "UUIDs vs4 shape" is a named benign near-miss shape distinct from
		// an arbitrary base64/hex blob of similar length, applied wherever
		// a candidate token is evaluated (both RedactPath's per-segment
		// pass and the general entropy pass share this helper).
		return false
	}
	if looksBase64OrHex(s) && len(s) >= 32 {
		return true
	}
	if len(s) < minLen {
		return false
	}
	return shannonEntropy(s) >= bitsPerChar
}
