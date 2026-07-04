//go:build js && wasm

// Command rana-verify-wasm is a WebAssembly build of the docs/TRUST.md §8
// independent verifier, for use inside a browser with NO server and NO
// network involved (assets/verifier/index.html is the companion viewer).
//
// It shares the exact same verification core as cmd/rana-verify-standalone
// — internal/exportverify — so a browser tab and a native CLI agree on
// every verdict by construction; this file's only job is to marshal
// JavaScript values (a browser has no filesystem, so a File's contents
// arrive as an ArrayBuffer) into the map[string][]byte shape
// exportverify.VerifyExportFiles expects, and marshal the Result back out
// as a plain JS object.
//
// This binary captures nothing: no prompts, no completions, no keystrokes
// (P7) — it reads only the five already-redacted export artifacts
// (docs/TRUST.md §7) the user drops onto the page, verifies them entirely
// client-side, and makes no network call (D24) of any kind.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o rana-verify.wasm ./cmd/rana-verify-wasm
//
// JS API (see assets/verifier/main.js for the consumer):
//
//	globalThis.ranaVerifyExport(filesObj) -> { verdict, reasonClass, reason, unattestedTail, externalPrevNotes }
//
//	filesObj is a plain JS object keyed by canonical export filename
//	(manifest.json / events.cbor / segments.cbor / checkpoints.cbor /
//	pubkey.pem), each value an ArrayBuffer (or Uint8Array) of that file's
//	bytes. A key may be omitted if the file is absent — exactly like a
//	missing file on disk.
package main

import (
	"syscall/js"

	"github.com/RNT56/RanA/internal/exportverify"
)

func main() {
	js.Global().Set("ranaVerifyExport", js.FuncOf(verifyExport))
	// Block forever: a wasm program that returns hands control back to the
	// JS event loop and its exported functions become uncallable.
	select {}
}

// verifyExport is the syscall/js-facing entry point registered as
// globalThis.ranaVerifyExport. It is intentionally synchronous (no
// goroutine/promise indirection) because internal/exportverify performs no
// I/O of its own — every byte it needs is already in the JS-supplied
// object — and keeping it synchronous makes the browser-side call site a
// plain function call rather than an async dance.
func verifyExport(this js.Value, args []js.Value) any {
	if len(args) != 1 {
		return jsError("ranaVerifyExport expects exactly one argument (an object of filename -> ArrayBuffer)")
	}
	files, err := filesFromJS(args[0])
	if err != nil {
		return jsError(err.Error())
	}

	res := exportverify.VerifyExportFiles(files)
	return resultToJS(res)
}

// filesFromJS converts the JS object {filename: ArrayBuffer|Uint8Array,
// ...} into exportverify's map[string][]byte input shape. Only the five
// canonical export filenames are read; unknown keys are ignored.
func filesFromJS(obj js.Value) (map[string][]byte, error) {
	names := []string{
		exportverify.FileManifest,
		exportverify.FileEvents,
		exportverify.FileSegments,
		exportverify.FileCheckpoint,
		exportverify.FilePubkey,
	}
	files := make(map[string][]byte, len(names))
	for _, name := range names {
		v := obj.Get(name)
		if v.IsUndefined() || v.IsNull() {
			continue
		}
		files[name] = bytesFromJSValue(v)
	}
	return files, nil
}

// bytesFromJSValue copies a JS ArrayBuffer or a typed array view
// (Uint8Array etc.) into a Go []byte. js.CopyBytesToGo requires a
// Uint8Array view, so an ArrayBuffer is wrapped in one first.
func bytesFromJSValue(v js.Value) []byte {
	uint8Array := js.Global().Get("Uint8Array")
	view := v
	// An ArrayBuffer has no .length; a typed array (Uint8Array etc.) does.
	// Wrap plain ArrayBuffers in a Uint8Array view before copying.
	if v.Get("constructor").Get("name").String() == "ArrayBuffer" {
		view = uint8Array.New(v)
	}
	length := view.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, view)
	return buf
}

// resultToJS marshals an exportverify.Result into the plain JS object
// shape assets/verifier/main.js consumes: a string verdict ("OK" |
// "BROKEN" | "INCOMPLETE"), plus the optional reason fields.
func resultToJS(res exportverify.Result) js.Value {
	out := js.Global().Get("Object").New()

	verdict := "OK"
	switch res.Code {
	case exportverify.CodeBroken:
		verdict = "BROKEN"
	case exportverify.CodeIncomplete:
		verdict = "INCOMPLETE"
	}
	out.Set("verdict", verdict)
	out.Set("reasonClass", res.ReasonClass)
	out.Set("reason", res.Reason)

	tail := js.Global().Get("Array").New(len(res.UnattestedTail))
	for i, u := range res.UnattestedTail {
		entry := js.Global().Get("Object").New()
		entry.Set("session", u.Session)
		entry.Set("seg", u.Seg)
		tail.SetIndex(i, entry)
	}
	out.Set("unattestedTail", tail)

	notes := js.Global().Get("Array").New(len(res.ExternalPrevNotes))
	for i, n := range res.ExternalPrevNotes {
		notes.SetIndex(i, n)
	}
	out.Set("externalPrevNotes", notes)

	return out
}

// jsError builds the same object shape as resultToJS's error-adjacent
// fields, for input errors detected before exportverify ever runs (e.g. a
// malformed call from JS) — reported as INCOMPLETE, matching
// docs/TRUST.md §6's "we could not verify" semantics, never a false
// BROKEN.
func jsError(msg string) js.Value {
	out := js.Global().Get("Object").New()
	out.Set("verdict", "INCOMPLETE")
	out.Set("reasonClass", "")
	out.Set("reason", msg)
	out.Set("unattestedTail", js.Global().Get("Array").New(0))
	out.Set("externalPrevNotes", js.Global().Get("Array").New(0))
	return out
}
