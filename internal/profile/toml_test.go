package profile

import (
	"reflect"
	"strings"
	"testing"
)

// The hand-rolled TOML subset parser (and its parseTOML/tomlDoc internal
// tests) was replaced by github.com/pelletier/go-toml/v2. The behaviors the
// old internal tests covered (comments, multi-line arrays, quoted-string
// escapes, syntax-error rejection) are re-asserted here at the Parse level —
// the only surface that still exists — so nothing regresses, plus the new
// robustness guarantees the spec-complete parser buys (duplicate-key and
// type-mismatch rejection).

// TestParse_CommentsAndMultilineArrays confirms the decoder handles the
// syntax the shipped packs actually use: full-line and trailing comments,
// and arrays that span multiple physical lines with a trailing comma.
func TestParse_CommentsAndMultilineArrays(t *testing.T) {
	src := `
# top-of-file comment
[profile]
name = "x" # trailing comment
description = "d"
version = 1

[sensitive_read]
# a comment inside a table
extra = [
  "~/.config/gh/**",
  "~/.npmrc",
  "~/.cargo/credentials*",
]
`
	p, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Name != "x" {
		t.Fatalf("Name = %q", p.Name)
	}
	want := []string{"~/.config/gh/**", "~/.npmrc", "~/.cargo/credentials*"}
	if !reflect.DeepEqual(p.SensitiveRead.Extra, want) {
		t.Fatalf("SensitiveRead.Extra = %#v, want %#v", p.SensitiveRead.Extra, want)
	}
}

// TestParse_EmptyArray confirms an explicitly empty array decodes to an empty
// (non-populated) slice, not an error.
func TestParse_EmptyArray(t *testing.T) {
	src := mustHeader() + "\n[digest]\nscopes = []\n"
	p, err := Parse(src, "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Digest.Scopes) != 0 {
		t.Fatalf("Digest.Scopes = %#v, want empty", p.Digest.Scopes)
	}
}

// TestParse_QuotedStringEscapes confirms standard TOML basic-string escapes
// are honored (the old hand-rolled parser only supported \" \\ \n \t; the
// real parser supports the full set).
func TestParse_QuotedStringEscapes(t *testing.T) {
	p, err := Parse("[profile]\nname = \"a\\\"b\\\\c\"\ndescription = \"d\"\nversion = 1\n", "test")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := `a"b\c`; p.Name != want {
		t.Fatalf("Name = %q, want %q", p.Name, want)
	}
}

// TestParse_MalformedTOMLRejected is the robustness gate the parser swap
// buys: go-toml/v2 rejects malformed, duplicate-keyed, wrong-typed, and
// truncated TOML with a clean error — never a panic, never silent
// acceptance. Each case must fail Parse.
func TestParse_MalformedTOMLRejected(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{
			name: "duplicate_key_in_table",
			src:  "[profile]\nname = \"a\"\nname = \"b\"\nversion = 1\n",
		},
		{
			name: "duplicate_table",
			src:  "[profile]\nname = \"a\"\nversion = 1\n[profile]\ndescription = \"d\"\n",
		},
		{
			name: "version_wrong_type_string",
			src:  "[profile]\nname = \"a\"\nversion = \"not-an-int\"\n",
		},
		{
			name: "auto_wrong_type_int",
			src:  mustHeader() + "\n[match]\nauto = 3\n",
		},
		{
			name: "exe_basename_wrong_type_scalar",
			src:  mustHeader() + "\n[match]\nexe_basename = \"claude\"\n",
		},
		{
			name: "capture_exec_wrong_type_string",
			src:  mustHeader() + "\n[capture]\nexec = \"yes\"\n",
		},
		{
			name: "unterminated_table_header",
			src:  "[profile\nname = \"x\"\n",
		},
		{
			name: "missing_value",
			src:  "[profile]\nname =\n",
		},
		{
			name: "missing_equals",
			src:  "[profile]\nname \"x\"\n",
		},
		{
			name: "unterminated_string",
			src:  "[profile]\nname = \"unterminated\n",
		},
		{
			name: "truncated_array",
			src:  mustHeader() + "\n[digest]\nscopes = [\"a\", \"b\"\n",
		},
		{
			name: "bare_key_outside_table",
			src:  "name = \"x\"\n",
		},
		{
			name: "entropy_threshold_wrong_type",
			src:  mustHeader() + "\n[redaction]\nentropy_threshold = \"high\"\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := func() (p *Profile, err error) {
				// Guard against a panic being mistaken for a pass.
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("Parse panicked on malformed input: %v", r)
					}
				}()
				return Parse(tc.src, "test")
			}()
			if err == nil {
				t.Fatalf("expected error for malformed input, got Profile %#v", p)
			}
		})
	}
}

// TestParse_ErrorReferencesSource confirms a decode error is still wrapped
// with the source name for a useful message.
func TestParse_ErrorReferencesSource(t *testing.T) {
	_, err := Parse("[profile]\nname = \"a\"\nname = \"b\"\n", "myfile.toml")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "myfile.toml") {
		t.Errorf("error should reference source name, got: %v", err)
	}
}
