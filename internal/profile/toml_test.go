package profile

import (
	"reflect"
	"testing"
)

func TestParseTOML_Basic(t *testing.T) {
	src := `
# comment
[profile]
name = "generic"
description = "hello world"
version = 1

[match]
auto = false
exe_basename = ["a", "b"]

[capture]
exec = true
fork_exit = false
`
	doc, err := parseTOML(src)
	if err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if got := doc.str("profile", "name"); got != "generic" {
		t.Fatalf("name = %q", got)
	}
	if got := doc.str("profile", "description"); got != "hello world" {
		t.Fatalf("description = %q", got)
	}
	if got := doc.int("profile", "version"); got != 1 {
		t.Fatalf("version = %d", got)
	}
	if got := doc.boolVal("match", "auto"); got != false {
		t.Fatalf("auto = %v", got)
	}
	if got := doc.strSlice("match", "exe_basename"); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("exe_basename = %#v", got)
	}
	if got := doc.boolVal("capture", "exec"); got != true {
		t.Fatalf("exec = %v", got)
	}
}

func TestParseTOML_MultilineArray(t *testing.T) {
	src := `
[sensitive_read]
extra = [
  "~/.config/gh/**",
  "~/.npmrc",
  "~/.cargo/credentials*",
]
`
	doc, err := parseTOML(src)
	if err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	want := []string{"~/.config/gh/**", "~/.npmrc", "~/.cargo/credentials*"}
	if got := doc.strSlice("sensitive_read", "extra"); !reflect.DeepEqual(got, want) {
		t.Fatalf("extra = %#v, want %#v", got, want)
	}
}

func TestParseTOML_EmptyArray(t *testing.T) {
	src := `
[digest]
scopes = []
`
	doc, err := parseTOML(src)
	if err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if got := doc.strSlice("digest", "scopes"); len(got) != 0 {
		t.Fatalf("scopes = %#v, want empty", got)
	}
}

func TestParseTOML_CommentsAndBlankLines(t *testing.T) {
	src := `
# top comment

[profile]
# a comment about name
name = "x" # trailing comment

[match]

auto = true
`
	doc, err := parseTOML(src)
	if err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if got := doc.str("profile", "name"); got != "x" {
		t.Fatalf("name = %q", got)
	}
	if got := doc.boolVal("match", "auto"); got != true {
		t.Fatalf("auto = %v", got)
	}
}

func TestParseTOML_MissingKeyDefaults(t *testing.T) {
	doc, err := parseTOML("[profile]\nname = \"x\"\n")
	if err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if got := doc.str("profile", "missing"); got != "" {
		t.Fatalf("missing str = %q", got)
	}
	if got := doc.strSlice("nosuch", "missing"); got != nil {
		t.Fatalf("missing slice = %#v", got)
	}
	if got := doc.boolVal("nosuch", "missing"); got != false {
		t.Fatalf("missing bool = %v", got)
	}
	if got := doc.int("nosuch", "missing"); got != 0 {
		t.Fatalf("missing int = %d", got)
	}
	if doc.has("nosuch", "missing") {
		t.Fatalf("has() true for missing key")
	}
}

func TestParseTOML_SyntaxErrors(t *testing.T) {
	cases := []string{
		"key = 1\n",                // key outside any table
		"[profile\nname = \"x\"\n", // unterminated table header
		"[profile]\nname = \n",     // missing value
		"[profile]\nname x\n",      // missing '='
		"[profile]\nname = \"unterminated\n",
	}
	for i, src := range cases {
		if _, err := parseTOML(src); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestParseTOML_EscapesInStrings(t *testing.T) {
	doc, err := parseTOML(`[profile]
name = "a\"b\\c"
`)
	if err != nil {
		t.Fatalf("parseTOML: %v", err)
	}
	if got, want := doc.str("profile", "name"), `a"b\c`; got != want {
		t.Fatalf("name = %q, want %q", got, want)
	}
}
