// Package report builds human-readable forensic reports from
// already-recorded, already-redacted RanA ledger events. Every function
// here is a pure reader: it never persists anything, never captures model
// I/O (P7), and never re-derives a fact the kernel could have provided
// from anything other than the recorded event stream itself (P1). See
// incident.go (narrative session report) and digest_diff.go (on-disk
// availability check for an fs.settle event).
package report

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/RNT56/RanA/internal/schema"
	"lukechampine.com/blake3"
)

// PathTranslator resolves the path recorded on an event to the path this
// process should read from local disk. On a plain Linux host this is the
// identity function; when the recorded session ran inside RanA's macOS
// microVM, paths are recorded in guest form (/mnt/host/<tag>/...) and must
// be translated back to the real host path before DigestDiff can read the
// file (internal/vm.PathXlate.GuestToHost implements this in production).
type PathTranslator interface {
	Translate(path string) (string, error)
}

// DigestDiffResult is the structured outcome of DigestDiff: whether the
// file currently on local disk matches the fs.settle event's recorded
// new_digest, without ever storing or transmitting the file's content.
type DigestDiffResult struct {
	// Path is the (translated) local filesystem path DigestDiff read.
	Path string
	// HaveNew reports whether the file currently on disk BLAKE3-digests to
	// exactly ev's new_digest — i.e. whether the recorded revision is
	// still (or again) present on disk.
	HaveNew bool
	// NewDigest is the recorded new_digest, hex-encoded, for display.
	NewDigest string
	// PrevDigest is the recorded prev_digest, hex-encoded, or "" if the
	// event carried none (e.g. a newly created file).
	PrevDigest string
	// Note is a one-line human-readable explanation of the outcome (match,
	// mismatch, missing file, read error), suitable for direct display in
	// a report — it never contains file content, only facts about the
	// comparison.
	Note string
}

// ErrNotFsSettle is returned by DigestDiff when given an event that is not
// an fs.settle event.
var ErrNotFsSettle = fmt.Errorf("report: DigestDiff requires an %s event", schema.EventTypeFsSettle)

// DigestDiff reconstructs before/after AVAILABILITY for an fs.settle event
// without ever storing file content: it reads the file currently on local
// disk at the (translated) recorded path, BLAKE3-digests it, and reports
// whether that digest matches the event's new_digest. It never persists or
// transmits file content — only the confirmation that a local file matches
// (or does not match) a recorded digest.
//
// tr translates the event's recorded path to a local filesystem path
// before reading (identity on a plain Linux host; guest->host translation
// when the session ran in RanA's macOS microVM). A nil tr is invalid.
func DigestDiff(tr PathTranslator, ev schema.Event) (DigestDiffResult, error) {
	if ev.Type != schema.EventTypeFsSettle {
		return DigestDiffResult{}, ErrNotFsSettle
	}
	if tr == nil {
		return DigestDiffResult{}, fmt.Errorf("report: DigestDiff: PathTranslator must not be nil")
	}

	recordedPath, ok := redactedField(ev.Data, "path")
	if !ok || recordedPath == "" {
		return DigestDiffResult{}, fmt.Errorf("report: fs.settle event missing path field")
	}
	newDigest, _ := ev.Data["new_digest"].([]byte)
	prevDigest, _ := ev.Data["prev_digest"].([]byte)

	res := DigestDiffResult{
		NewDigest:  hex.EncodeToString(newDigest),
		PrevDigest: hex.EncodeToString(prevDigest),
	}

	localPath, err := tr.Translate(recordedPath)
	if err != nil {
		res.Path = recordedPath
		res.Note = fmt.Sprintf("path could not be translated to a local path: %v", err)
		return res, nil
	}
	res.Path = localPath

	// Stat before opening and require a regular file. Without this, a path
	// that currently resolves to a FIFO, character device, or other special
	// file (attacker-controlled or merely coincidental on-disk state — the
	// path recorded on the event does not guarantee what sits there now)
	// would cause the subsequent io.Copy to block indefinitely on a FIFO
	// with no writer, or read a live device, turning report generation into
	// a denial of service. DigestDiff only ever needs to read plain file
	// content to hash it, so anything else is reported, never opened.
	info, err := os.Lstat(localPath)
	if err != nil {
		if os.IsNotExist(err) {
			res.Note = "file is not present on local disk (deleted, moved, or never materialized here)"
			return res, nil
		}
		res.Note = fmt.Sprintf("file could not be read: %v", err)
		return res, nil
	}
	if !info.Mode().IsRegular() {
		res.Note = "path on local disk is not a regular file (symlink, device, FIFO, or similar) — refusing to read"
		return res, nil
	}

	f, err := os.Open(localPath)
	if err != nil {
		if os.IsNotExist(err) {
			res.Note = "file is not present on local disk (deleted, moved, or never materialized here)"
			return res, nil
		}
		res.Note = fmt.Sprintf("file could not be read: %v", err)
		return res, nil
	}
	defer f.Close()

	h := blake3.New(32, nil)
	if _, err := io.Copy(h, f); err != nil {
		res.Note = fmt.Sprintf("file could not be read: %v", err)
		return res, nil
	}
	onDisk := h.Sum(nil)

	if len(newDigest) > 0 && hex.EncodeToString(onDisk) == res.NewDigest {
		res.HaveNew = true
		res.Note = "on-disk content matches the recorded new_digest: this revision is present on disk"
	} else {
		res.Note = "on-disk content does NOT match the recorded new_digest: the file has changed since, or the recorded digest is unavailable"
	}
	return res, nil
}
