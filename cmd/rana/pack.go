package main

import (
	"archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/klauspost/compress/zstd"
)

// viewerAssetFiles are the checked-in verifier viewer files (assets/
// verifier/BUILD.md) that a proof pack bundles when present. The two build
// artifacts BUILD.md documents (rana-verify.wasm, wasm_exec.js) are
// intentionally not checked into the repo, so they are included only when
// found on disk at pack time (e.g. a release build produced them first) —
// their absence does not fail the pack (see writeProofPack's doc comment).
var viewerAssetFiles = []string{"index.html", "main.js", "style.css", "rana-verify.wasm", "wasm_exec.js"}

// verifierAssetsDir locates the assets/verifier directory on disk relative
// to this source file, so `rana export --pack` can find the viewer
// regardless of the caller's working directory. It is a var (not a plain
// func) so tests can point it at a missing directory to exercise the
// non-fatal-absence path without touching the real repo tree.
var verifierAssetsDir = func() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// this file lives at <repo>/cmd/rana/pack.go
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "assets", "verifier")
}

// writeProofPack bundles an already-produced export directory (exportDir,
// as written by ledger.Export: manifest.json/events.cbor/segments.cbor/
// checkpoints.cbor/pubkey.pem, plus the human-readable .jsonl siblings)
// together with the offline verifier viewer (assets/verifier) into a
// single self-contained tar+zstd archive at packPath, named
// "<session>.ranaproof" by convention (the caller chooses packPath).
//
// The pack is organized as:
//
//	exports/...   the exact contents of exportDir (unmodified)
//	viewer/...    assets/verifier's checked-in viewer files, plus the
//	              rana-verify.wasm/wasm_exec.js build artifacts if they
//	              happen to be present on disk (assets/verifier/BUILD.md)
//	OPEN_ME.txt   plain-text instructions for a recipient with no RanA
//	              install: build the viewer, or run rana-verify-standalone
//
// A missing viewer directory (e.g. a stripped install, or wasm not built)
// is NOT an error: the proof pack's actual trust value is the export
// artifacts themselves, independently re-verifiable per docs/TRUST.md §8
// by anyone re-implementing that spec — the bundled viewer is a
// convenience for recipients who don't want to do that, never a
// requirement (P4: claim exactly what the pack delivers).
func writeProofPack(exportDir, packPath, session string) error {
	if err := os.MkdirAll(filepath.Dir(packPath), 0o755); err != nil {
		return fmt.Errorf("rana export --pack: creating output directory: %w", err)
	}
	f, err := os.Create(packPath)
	if err != nil {
		return fmt.Errorf("rana export --pack: creating %s: %w", packPath, err)
	}
	defer f.Close()

	zw, err := zstd.NewWriter(f)
	if err != nil {
		return fmt.Errorf("rana export --pack: starting zstd writer: %w", err)
	}

	tw := tar.NewWriter(zw)

	if err := addDirToTar(tw, exportDir, "exports"); err != nil {
		return fmt.Errorf("rana export --pack: bundling export files: %w", err)
	}

	if vdir := verifierAssetsDir(); vdir != "" {
		if fi, err := os.Stat(vdir); err == nil && fi.IsDir() {
			for _, name := range viewerAssetFiles {
				src := filepath.Join(vdir, name)
				b, err := os.ReadFile(src)
				if err != nil {
					continue // optional file (e.g. wasm not built) — skip, not fatal
				}
				if err := writeTarFile(tw, "viewer/"+name, b); err != nil {
					return fmt.Errorf("rana export --pack: bundling viewer asset %s: %w", name, err)
				}
			}
		}
	}

	openMe := proofPackReadme(session)
	if err := writeTarFile(tw, "OPEN_ME.txt", []byte(openMe)); err != nil {
		return fmt.Errorf("rana export --pack: writing OPEN_ME.txt: %w", err)
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("rana export --pack: finalizing tar: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("rana export --pack: finalizing zstd: %w", err)
	}
	return f.Close()
}

// proofPackReadme is the plain-text note bundled at the pack root so a
// recipient with zero RanA context knows what they're holding and how to
// check it, without RanA ever needing to be installed.
func proofPackReadme(session string) string {
	return fmt.Sprintf(`RanA proof pack — session %s

This is a self-contained, independently-verifiable record of one RanA
recording session (docs/TRUST.md). It contains:

  exports/   the signed, hash-chained export (docs/TRUST.md §7):
             manifest.json, events.cbor, segments.cbor, checkpoints.cbor,
             pubkey.pem, plus human-readable .jsonl siblings (NOT hashed —
             for reading only; verification uses the .cbor files).
  viewer/    (if present) an offline HTML+WebAssembly viewer that
             independently re-derives every hash and signature in your
             browser, with no install and no network call. Open
             viewer/index.html and drop the exports/ files onto it.

To verify without the bundled viewer:

  rana-verify-standalone exports/

Verification recomputes every leaf hash, Merkle root, segment chain link,
and Ed25519 signature from the raw bytes in exports/ — it trusts nothing
about how this pack was produced. See docs/TRUST.md and LIMITS.md for
exactly what a passing verification does and does not prove.
`, session)
}

// addDirToTar copies every regular file directly under dir (non-recursive
// — ledger.Export writes a flat directory of exactly the documented
// export artifacts, docs/TRUST.md §7) into tw under prefix/<name>.
func addDirToTar(tw *tar.Writer, dir, prefix string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if err := writeTarFile(tw, prefix+"/"+e.Name(), b); err != nil {
			return err
		}
	}
	return nil
}

func writeTarFile(tw *tar.Writer, name string, content []byte) error {
	hdr := &tar.Header{
		Name: name,
		Mode: 0o644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(content)
	return err
}
