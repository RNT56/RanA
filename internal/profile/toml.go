package profile

import (
	"fmt"
	"strconv"
	"strings"
)

// tomlDoc is a parsed TOML document restricted to the subset RanA's profile
// packs actually use (CONTRACTS.md internal/profile): top-level `[section]`
// tables (no nesting, no arrays-of-tables, no dotted keys, no inline
// tables) holding string, bool, integer, and string-array values.
//
// This hand-rolled parser exists because github.com/pelletier/go-toml/v2 is
// listed as an allowed import in the build contract but is NOT present in
// go.mod/go.sum, and CONTRACTS.md/CLAUDE.md forbid editing go.mod. Rather
// than add an undeclared dependency, profile.toml files are parsed with this
// deliberately small, well-tested subset parser (see final report for this
// contract/repo-state conflict).
type tomlDoc struct {
	sections map[string]map[string]tomlValue
	// order preserves table declaration order for deterministic iteration
	// where callers care (not currently required, kept for debuggability).
	order []string
}

type tomlKind int

const (
	kindString tomlKind = iota
	kindBool
	kindInt
	kindFloat
	kindStringArray
)

type tomlValue struct {
	kind   tomlKind
	str    string
	b      bool
	i      int64
	f      float64
	strArr []string
}

func newTomlDoc() *tomlDoc {
	return &tomlDoc{sections: make(map[string]map[string]tomlValue)}
}

func (d *tomlDoc) has(section, key string) bool {
	tbl, ok := d.sections[section]
	if !ok {
		return false
	}
	_, ok = tbl[key]
	return ok
}

func (d *tomlDoc) str(section, key string) string {
	if v, ok := d.get(section, key); ok && v.kind == kindString {
		return v.str
	}
	return ""
}

func (d *tomlDoc) boolVal(section, key string) bool {
	if v, ok := d.get(section, key); ok && v.kind == kindBool {
		return v.b
	}
	return false
}

func (d *tomlDoc) int(section, key string) int64 {
	if v, ok := d.get(section, key); ok && v.kind == kindInt {
		return v.i
	}
	return 0
}

// float64Val returns a numeric value (int or float literal) as a float64.
func (d *tomlDoc) float64Val(section, key string) float64 {
	v, ok := d.get(section, key)
	if !ok {
		return 0
	}
	switch v.kind {
	case kindFloat:
		return v.f
	case kindInt:
		return float64(v.i)
	default:
		return 0
	}
}

func (d *tomlDoc) strSlice(section, key string) []string {
	if v, ok := d.get(section, key); ok && v.kind == kindStringArray {
		return v.strArr
	}
	return nil
}

func (d *tomlDoc) get(section, key string) (tomlValue, bool) {
	tbl, ok := d.sections[section]
	if !ok {
		return tomlValue{}, false
	}
	v, ok := tbl[key]
	return v, ok
}

// hasSection reports whether the document declared the given table at all
// (as opposed to the table simply having no matching key).
func (d *tomlDoc) hasSection(section string) bool {
	_, ok := d.sections[section]
	return ok
}

// parseTOML parses src under the restricted grammar documented on tomlDoc.
// Errors report a 1-indexed line number.
func parseTOML(src string) (*tomlDoc, error) {
	doc := newTomlDoc()
	lines := strings.Split(src, "\n")

	var curSection string
	haveSection := false

	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		raw := lines[i]
		line := stripComment(raw)
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("profile: line %d: unterminated table header", lineNo)
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" {
				return nil, fmt.Errorf("profile: line %d: empty table name", lineNo)
			}
			if strings.ContainsAny(name, "\"'.") {
				return nil, fmt.Errorf("profile: line %d: unsupported table name %q (nested/quoted tables not supported)", lineNo, name)
			}
			curSection = name
			haveSection = true
			if _, ok := doc.sections[curSection]; !ok {
				doc.sections[curSection] = make(map[string]tomlValue)
				doc.order = append(doc.order, curSection)
			}
			continue
		}

		if !haveSection {
			return nil, fmt.Errorf("profile: line %d: key outside any [table]", lineNo)
		}

		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, fmt.Errorf("profile: line %d: expected 'key = value'", lineNo)
		}
		key := strings.TrimSpace(line[:eq])
		if key == "" {
			return nil, fmt.Errorf("profile: line %d: empty key", lineNo)
		}
		if !isValidKey(key) {
			return nil, fmt.Errorf("profile: line %d: invalid key %q", lineNo, key)
		}
		valText := strings.TrimSpace(line[eq+1:])

		var (
			val     tomlValue
			consumd int
			err     error
		)
		if strings.HasPrefix(valText, "[") {
			val, consumd, err = parseArrayValue(lines, i, valText, lineNo)
			if err != nil {
				return nil, err
			}
			i = consumd
		} else {
			val, err = parseScalarValue(valText, lineNo)
			if err != nil {
				return nil, err
			}
		}
		doc.sections[curSection][key] = val
	}

	return doc, nil
}

func isValidKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if !(r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// stripComment removes a trailing `# ...` comment, honoring '#' inside a
// double-quoted string so a literal '#' in a value is not truncated.
func stripComment(line string) string {
	inStr := false
	escaped := false
	for i, r := range line {
		if inStr {
			if escaped {
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '"':
				inStr = false
			}
			continue
		}
		switch r {
		case '"':
			inStr = true
		case '#':
			return line[:i]
		}
	}
	return line
}

// parseScalarValue parses a bool, integer, or quoted-string TOML value.
func parseScalarValue(text string, lineNo int) (tomlValue, error) {
	switch text {
	case "":
		return tomlValue{}, fmt.Errorf("profile: line %d: missing value", lineNo)
	case "true":
		return tomlValue{kind: kindBool, b: true}, nil
	case "false":
		return tomlValue{kind: kindBool, b: false}, nil
	}
	if strings.HasPrefix(text, `"`) {
		s, err := parseQuotedString(text, lineNo)
		if err != nil {
			return tomlValue{}, err
		}
		return tomlValue{kind: kindString, str: s}, nil
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return tomlValue{kind: kindInt, i: n}, nil
	}
	if f, err := strconv.ParseFloat(text, 64); err == nil {
		return tomlValue{kind: kindFloat, f: f}, nil
	}
	return tomlValue{}, fmt.Errorf("profile: line %d: unsupported value %q", lineNo, text)
}

// parseQuotedString parses a single double-quoted TOML basic string,
// supporting \" and \\ escapes (the only escapes RanA's shipped packs use).
// text must start with '"' and, after unescaping, end with an unescaped '"'.
func parseQuotedString(text string, lineNo int) (string, error) {
	if len(text) < 2 || text[0] != '"' {
		return "", fmt.Errorf("profile: line %d: malformed string %q", lineNo, text)
	}
	var b strings.Builder
	i := 1
	closed := false
	for i < len(text) {
		c := text[i]
		if c == '\\' {
			if i+1 >= len(text) {
				return "", fmt.Errorf("profile: line %d: dangling escape in string", lineNo)
			}
			next := text[i+1]
			switch next {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				return "", fmt.Errorf("profile: line %d: unsupported escape \\%c", lineNo, next)
			}
			i += 2
			continue
		}
		if c == '"' {
			closed = true
			i++
			break
		}
		b.WriteByte(c)
		i++
	}
	if !closed {
		return "", fmt.Errorf("profile: line %d: unterminated string", lineNo)
	}
	if strings.TrimSpace(text[i:]) != "" {
		return "", fmt.Errorf("profile: line %d: trailing content after string: %q", lineNo, text[i:])
	}
	return b.String(), nil
}

// parseArrayValue parses a `[ ... ]` string array, which may span multiple
// physical lines. startIdx is the 0-indexed line the key/value assignment
// began on; firstText is that line's text after '='. Returns the parsed
// value and the 0-indexed line number of the line containing the closing
// ']', for the caller to resume scanning after.
func parseArrayValue(lines []string, startIdx int, firstText string, startLineNo int) (tomlValue, int, error) {
	var items []string
	body := firstText
	lineNo := startLineNo
	idx := startIdx

	// Accumulate lines until we see the closing ']'.
	for {
		closeAt := indexUnquotedRBracket(body)
		if closeAt >= 0 {
			inner := body[1:closeAt]
			if err := appendArrayItems(&items, inner, lineNo); err != nil {
				return tomlValue{}, idx, err
			}
			trailing := strings.TrimSpace(stripComment(body[closeAt+1:]))
			if trailing != "" {
				return tomlValue{}, idx, fmt.Errorf("profile: line %d: trailing content after array: %q", lineNo, trailing)
			}
			return tomlValue{kind: kindStringArray, strArr: items}, idx, nil
		}
		// No closing bracket on this physical line yet: consume the whole
		// line (minus comment) as array content and continue to the next.
		if err := appendArrayItems(&items, body[1:], lineNo); err != nil {
			return tomlValue{}, idx, err
		}
		idx++
		if idx >= len(lines) {
			return tomlValue{}, idx, fmt.Errorf("profile: line %d: unterminated array", startLineNo)
		}
		lineNo = idx + 1
		body = "[" + stripComment(lines[idx])
	}
}

// indexUnquotedRBracket returns the index of the first ']' in s that is not
// inside a double-quoted string, or -1 if none.
func indexUnquotedRBracket(s string) int {
	inStr := false
	escaped := false
	for i, r := range s {
		if inStr {
			if escaped {
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '"':
				inStr = false
			}
			continue
		}
		switch r {
		case '"':
			inStr = true
		case ']':
			return i
		}
	}
	return -1
}

// appendArrayItems splits a comma-separated run of quoted-string array
// items (possibly empty/whitespace-only) and appends them to items.
func appendArrayItems(items *[]string, segment string, lineNo int) error {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return nil
	}
	for _, part := range splitTopLevelCommas(segment) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		s, err := parseQuotedString(part, lineNo)
		if err != nil {
			return err
		}
		*items = append(*items, s)
	}
	return nil
}

// splitTopLevelCommas splits s on commas that are not inside a
// double-quoted string, dropping a trailing empty element (trailing comma).
func splitTopLevelCommas(s string) []string {
	var out []string
	var cur strings.Builder
	inStr := false
	escaped := false
	for _, r := range s {
		if inStr {
			cur.WriteRune(r)
			if escaped {
				escaped = false
				continue
			}
			switch r {
			case '\\':
				escaped = true
			case '"':
				inStr = false
			}
			continue
		}
		switch r {
		case '"':
			inStr = true
			cur.WriteRune(r)
		case ',':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}
