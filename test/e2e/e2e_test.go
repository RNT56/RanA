// Package e2e is RanA's full-path integration suite: it drives a realistic
// event stream through the REAL wire framing → session service → ledger →
// verify → export → independent standalone verifier, entirely on the host
// (no kernel, no VM needed), and asserts the trust and secret-freedom
// properties end to end. It is what `make test-e2e` runs.
package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/cborcanon"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
	"github.com/RNT56/RanA/internal/service"
	"github.com/RNT56/RanA/internal/wire"

	_ "modernc.org/sqlite"
)

// harness builds a real ledger + a RanadServer in front of it, and returns a
// function that feeds a slice of events through the real wire codec (as ranad
// would) and a teardown that seals + closes the ledger.
type harness struct {
	root       string
	dir        ledger.Datadir
	writer     *ledger.Writer
	server     *service.RanadServer
	salt       []byte
	decodeErrs []error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	d := ledger.Dir(root)
	if err := d.Ensure(); err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	salt, err := d.LoadOrCreateSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	key, err := chain.GenerateKey(root)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	w, err := ledger.NewWriter(d, ledger.WriterOptions{
		SegSealMaxEvents:  5,
		CheckpointMaxSegs: 2,
		Key:               key,
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	h := &harness{root: root, dir: d, writer: w, salt: salt}
	srv := service.NewRanadServer(service.RanadServerConfig{
		Appender:      w,
		OnDecodeError: func(err error) { h.decodeErrs = append(h.decodeErrs, err) },
	})
	h.server = srv
	return h
}

// feed streams events through the real wire framing into the RanadServer,
// exactly as the ranad daemon would over its unix socket.
func (h *harness) feed(t *testing.T, events []schema.Event) {
	t.Helper()
	client, serverSide := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- h.server.HandleConn(serverSide) }()

	if err := wire.WriteFrame(client, &wire.Hello{V: wire.Version, Role: wire.RoleRanad, Salt: h.salt}); err != nil {
		t.Fatalf("hello: %v", err)
	}
	for i, ev := range events {
		enc, err := cborcanon.EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode event %d: %v", i, err)
		}
		if err := wire.WriteFrame(client, &wire.Ev{Event: enc}); err != nil {
			t.Fatalf("write ev %d: %v", i, err)
		}
	}
	if err := wire.WriteFrame(client, &wire.Bye{}); err != nil {
		t.Fatalf("bye: %v", err)
	}
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleConn: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out feeding events")
	}
	if err := h.writer.FlushForTest(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if len(h.decodeErrs) > 0 {
		t.Fatalf("ranad server reported %d decode/append errors, first: %v", len(h.decodeErrs), h.decodeErrs[0])
	}
}

func (h *harness) sealClose(t *testing.T, sessions ...string) {
	t.Helper()
	for _, s := range sessions {
		if err := h.writer.SealSession(s); err != nil {
			t.Fatalf("SealSession %s: %v", s, err)
		}
	}
	if err := h.writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// realisticStream synthesizes a session's worth of mixed effect events.
func realisticStream(session string, base uint64) []schema.Event {
	R := redact.Literal
	daddr := make([]byte, 16)
	daddr[10], daddr[11] = 0xff, 0xff
	daddr[12], daddr[13], daddr[14], daddr[15] = 93, 184, 216, 34
	var evs []schema.Event
	add := func(ev schema.Event) { evs = append(evs, ev) }
	i := func() uint64 { base++; return base }
	add(schema.NewSessionStart(session, 0, i(), base, base, 0, R("generic"), nil, map[string]any{}, nil))
	add(schema.NewProcExec(session, 0, i(), base, base, 100,
		[]redact.Redacted{R("/bin/sh"), R("-c"), R("curl example.com")}, R("sh"), R("/home/u"), R("/bin/sh"), 1, 1000))
	add(schema.NewNetConnect(session, 0, i(), base, base, 100, "tcp", daddr, 443, "inet"))
	add(schema.NewFsWriteOpen(session, 0, i(), base, base, 100, R("/home/u/out.txt"), schema.PathSourceResolved, 0x241, 0o644))
	add(schema.NewFsSensitiveRead(session, 0, i(), base, base, 100, R("/home/u/.ssh/id_ed25519"), R("ssh-key")))
	return evs
}

// TestE2E_RecordVerifyExportStandalone is the headline path: a recorded
// session verifies OK, exports a portable proof pack, and that pack passes
// the INDEPENDENT standalone verifier (a third party with no RanA installed);
// then a tampered ledger is caught as BROKEN.
func TestE2E_RecordVerifyExportStandalone(t *testing.T) {
	h := newHarness(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5F00"
	// Feed three streams' worth so we get multiple segments + a checkpoint.
	h.feed(t, realisticStream(session, 1_000_000_000))
	h.feed(t, realisticStream(session, 2_000_000_000))
	h.feed(t, realisticStream(session, 3_000_000_000))
	h.sealClose(t, session)

	// 1) internal verify: OK.
	res, err := ledger.Verify(h.dir, ledger.VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Code != ledger.CodeOK {
		t.Fatalf("clean ledger verify code = %d, want 0; findings=%v", res.Code, res.Findings)
	}

	// 2) export + independent standalone verifier: OK (exit 0).
	exportDir := filepath.Join(t.TempDir(), "export")
	if err := ledger.Export(h.dir, session, exportDir); err != nil {
		t.Fatalf("Export: %v", err)
	}
	verifier := buildStandaloneVerifier(t)
	if code, out := runVerifier(t, verifier, exportDir); code != 0 {
		t.Fatalf("standalone verifier on clean export = %d, want 0\n%s", code, out)
	}

	// 3) Tamper the EXPORTED proof pack itself (the real third-party threat:
	// someone alters an export they were handed) → the independent verifier
	// must report BROKEN (2). We flip a byte inside events.cbor; the leaf is
	// BLAKE3 of the exact bytes, so any change breaks the merkle root.
	tampered := filepath.Join(t.TempDir(), "tampered")
	copyExport(t, exportDir, tampered)
	flipByteInFile(t, filepath.Join(tampered, "events.cbor"))
	if code, out := runVerifier(t, verifier, tampered); code != 2 {
		t.Fatalf("standalone verifier on tampered export = %d, want 2 (BROKEN)\n%s", code, out)
	}
}

// TestE2E_RedactionKeepsSecretsOffDisk is the P3 end-to-end: an event carrying
// a seeded secret in argv is redacted before it is hashed and persisted, so
// the raw secret never appears in the on-disk ledger — and the redaction
// marker proves the pipeline actually fired (not that the secret was merely
// omitted).
func TestE2E_RedactionKeepsSecretsOffDisk(t *testing.T) {
	h := newHarness(t)
	session := "01ARZ3NDEKTSV4RRFFQ69G5F11"

	// Split so the literal AWS-key shape isn't in this source file either.
	secret := "AKIA" + "7Q2X9ZK4M1N8B6VC"
	p, err := redact.NewPipeline(h.salt)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	argv := p.RedactArgv([]string{"/usr/bin/aws", "--key", secret})

	ev := schema.NewProcExec(session, 0, 1, 1_000, 1_000, 100,
		argv, redact.Literal("aws"), redact.Literal("/home/u"), redact.Literal("/usr/bin/aws"), 1, 1000)
	// session.start first so the ledger has a valid session opener.
	start := schema.NewSessionStart(session, 0, 0, 500, 500, 0, redact.Literal("generic"), nil, map[string]any{}, nil)
	h.feed(t, []schema.Event{start, ev})
	h.sealClose(t, session)

	// Read every persisted event's canonical bytes via SQL (which sees WAL
	// content, unlike reading the raw db file). The raw secret must appear in
	// none of them, and at least one must carry a redaction marker — proving
	// the pipeline fired rather than the secret merely being absent.
	raw := allEventBytes(t, h.dir)
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("RAW SECRET FOUND IN LEDGER ON DISK — P3 violated end to end")
	}
	if !bytes.Contains(raw, []byte("⟦R:")) { // ⟦R:  redaction marker
		t.Fatal("no redaction marker in ledger — the pipeline may not have fired")
	}
}

// allEventBytes concatenates every stored event's canonical CBOR bytes,
// read via SQL so WAL-resident rows are included.
func allEventBytes(t *testing.T, dir ledger.Datadir) []byte {
	t.Helper()
	db, err := sql.Open("sqlite", dir.DBPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT bytes FROM events ORDER BY rowid`)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	defer rows.Close()
	var all []byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatalf("scan: %v", err)
		}
		all = append(all, b...)
	}
	return all
}

// TestE2E_TwoSessionsRemainDistinct proves cross-agent attribution: two
// sessions recorded into one ledger stay distinct (not merged into one blob),
// and the whole ledger still verifies.
func TestE2E_TwoSessionsRemainDistinct(t *testing.T) {
	h := newHarness(t)
	s1 := "01ARZ3NDEKTSV4RRFFQ69G5FA1"
	s2 := "01ARZ3NDEKTSV4RRFFQ69G5FB2"
	h.feed(t, realisticStream(s1, 1_000_000_000))
	h.feed(t, realisticStream(s2, 2_000_000_000))
	h.sealClose(t, s1, s2)

	ds, err := service.NewLedgerDataSource(h.dir)
	if err != nil {
		t.Fatalf("NewLedgerDataSource: %v", err)
	}
	sessions, err := ds.Sessions(context.Background())
	if err != nil {
		t.Fatalf("Sessions: %v", err)
	}
	ids := map[string]bool{}
	for _, s := range sessions {
		ids[s.ID] = true
	}
	if !ids[s1] || !ids[s2] {
		t.Fatalf("expected both sessions distinct, got %v", ids)
	}
	res, err := ledger.Verify(h.dir, ledger.VerifyOptions{})
	if err != nil || res.Code != ledger.CodeOK {
		t.Fatalf("two-session ledger verify: code=%d err=%v", res.Code, err)
	}
}

// ---- helpers ----

func buildStandaloneVerifier(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "rana-verify-standalone")
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd/rana-verify-standalone")
	var errb bytes.Buffer
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("building standalone verifier: %v\n%s", err, errb.String())
	}
	return bin
}

func runVerifier(t *testing.T, bin, exportDir string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, exportDir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err == nil {
		return 0, out.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String()
	}
	t.Fatalf("running verifier: %v", err)
	return -1, out.String()
}

// copyExport copies every file in src into a fresh dst directory.
func copyExport(t *testing.T, src, dst string) {
	t.Helper()
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", e.Name(), err)
		}
	}
}

// flipByteInFile flips one byte near the middle of a file, corrupting the
// canonical event bytes without disturbing the file's length framing at the
// edges.
func flipByteInFile(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(b) < 8 {
		t.Fatalf("%s too small to tamper", path)
	}
	b[len(b)/2] ^= 0xFF
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
