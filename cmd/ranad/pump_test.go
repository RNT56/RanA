package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/collector"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/wire"
)

// ---- test fakes ----

// fakeClock is an injectable collector.Clock for deterministic pump tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeSource is a scripted RecordSource: it yields a fixed list of raw
// records (or an error/EOF signal) without touching any real ring buffer,
// so the orchestration logic is fully testable on darwin (CONTRACTS: "the
// bpf attach is the only linux-gated part").
type fakeSource struct {
	mu      sync.Mutex
	records [][]byte
	i       int
	closed  bool
}

func (s *fakeSource) Next() ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, errSourceClosed
	}
	if s.i >= len(s.records) {
		return nil, false, nil
	}
	rec := s.records[s.i]
	s.i++
	return rec, true, nil
}

func (s *fakeSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

var errSourceClosed = errors.New("fakeSource: closed")

// fakeSink is an in-memory FrameSink: Send appends to a slice, and a
// pre-loaded inbound queue feeds Recv, so heads.log wiring can be tested
// without a real unix socket.
type fakeSink struct {
	mu      sync.Mutex
	sent    []wire.Frame
	inbound []wire.Frame
	closed  bool
	sendErr error
}

func (s *fakeSink) Send(f wire.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendErr != nil {
		return s.sendErr
	}
	s.sent = append(s.sent, f)
	return nil
}

func (s *fakeSink) Recv() (wire.Frame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inbound) == 0 {
		return nil, ErrNoMoreFrames
	}
	f := s.inbound[0]
	s.inbound = s.inbound[1:]
	return f, nil
}

func (s *fakeSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *fakeSink) Sent() []wire.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]wire.Frame, len(s.sent))
	copy(out, s.sent)
	return out
}

// ---- record builders ----

func buildForkRecord(pid, ppid uint32, cgid uint64, tsMono, tsWall uint64) []byte {
	buf := make([]byte, collector.SizeForkRecord)
	buf[0] = 1 // version
	buf[1] = collector.RecordKindFork
	binary.LittleEndian.PutUint32(buf[2:6], pid)
	binary.LittleEndian.PutUint32(buf[6:10], ppid)
	binary.LittleEndian.PutUint64(buf[10:18], cgid)
	binary.LittleEndian.PutUint64(buf[18:26], tsMono)
	binary.LittleEndian.PutUint64(buf[26:34], tsWall)
	return buf
}

func buildExitRecord(pid uint32, cgid uint64, tsMono, tsWall uint64, exitCode int32) []byte {
	buf := make([]byte, collector.SizeExitRecord)
	buf[0] = 1
	buf[1] = collector.RecordKindExit
	binary.LittleEndian.PutUint32(buf[2:6], pid)
	binary.LittleEndian.PutUint64(buf[6:14], cgid)
	binary.LittleEndian.PutUint64(buf[14:22], tsMono)
	binary.LittleEndian.PutUint64(buf[22:30], tsWall)
	binary.LittleEndian.PutUint32(buf[30:34], uint32(exitCode))
	// remaining bytes (utime_ns, stime_ns) default to zero, which is fine.
	return buf
}

// ---- newTestPump helper ----

func newTestPump(t *testing.T, clk *fakeClock, cgid uint64, session string) (*Pump, *fakeSource, *fakeSink) {
	t.Helper()
	pipeline, err := redact.NewPipeline([]byte("test-salt-0123456789"))
	if err != nil {
		t.Fatalf("redact.NewPipeline: %v", err)
	}
	enricher := collector.NewEnricher(collector.EnricherConfig{
		Pipeline: pipeline,
		DNSCache: collector.NewDNSCache(clk),
		Clock:    clk,
	})
	enricher.BindCgid(cgid, session)

	gov, err := collector.NewGovernor(collector.GovernorConfig{
		Clock:        clk,
		RatePerSec:   1_000_000,
		BurstSize:    1_000_000,
		ShedInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}

	src := &fakeSource{}
	sink := &fakeSink{}

	p := NewPump(PumpConfig{
		Source:      src,
		Sink:        sink,
		Enricher:    enricher,
		Governor:    gov,
		Clock:       clk,
		HeadsLogDir: t.TempDir(),
	})
	return p, src, sink
}

// ---- tests ----

func TestPump_DecodesEnrichesAndSendsFrame(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p, src, sink := newTestPump(t, clk, 42, "sess1")

	src.records = [][]byte{
		buildForkRecord(100, 1, 42, 111, 222),
	}

	n, err := p.Drain()
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if n != 1 {
		t.Fatalf("Drain processed = %d, want 1", n)
	}

	sent := sink.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent frames = %d, want 1", len(sent))
	}
	ev, ok := sent[0].(*wire.Ev)
	if !ok {
		t.Fatalf("sent[0] = %T, want *wire.Ev", sent[0])
	}
	if len(ev.Event) == 0 {
		t.Fatal("sent Ev frame has empty Event bytes")
	}
}

func TestPump_UnknownCgidRecordIsSkippedNotFatal(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p, src, sink := newTestPump(t, clk, 42, "sess1")

	// cgid 999 was never bound: Enricher returns ErrUnknownCgid. The pump
	// must not treat this as a fatal error (kernel-filtered events for
	// foreign cgroups should never reach here per D6, but a defensive path
	// must not crash the daemon over it) and must not emit a frame for it.
	src.records = [][]byte{
		buildForkRecord(100, 1, 999, 111, 222),
		buildForkRecord(101, 1, 42, 333, 444),
	}

	n, err := p.Drain()
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if n != 2 {
		t.Fatalf("Drain processed = %d, want 2", n)
	}

	sent := sink.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent frames = %d, want 1 (unknown-cgid record must be skipped)", len(sent))
	}
}

func TestPump_GarbageRecordIsSkippedNotFatal(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p, src, sink := newTestPump(t, clk, 42, "sess1")

	src.records = [][]byte{
		{0xff, 0xff, 0x01, 0x02}, // garbage: bad version
		buildForkRecord(101, 1, 42, 333, 444),
	}

	n, err := p.Drain()
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if n != 2 {
		t.Fatalf("Drain processed = %d, want 2", n)
	}
	if len(sink.Sent()) != 1 {
		t.Fatalf("sent frames = %d, want 1", len(sink.Sent()))
	}
}

func TestPump_GovernorShedsAndFlushGapsEmitsGapEvent(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	pipeline, err := redact.NewPipeline([]byte("test-salt-0123456789"))
	if err != nil {
		t.Fatalf("redact.NewPipeline: %v", err)
	}
	enricher := collector.NewEnricher(collector.EnricherConfig{
		Pipeline: pipeline,
		DNSCache: collector.NewDNSCache(clk),
		Clock:    clk,
	})
	enricher.BindCgid(42, "sess1")

	// Burst size of 1, high shed pressure: the second fork/exit-class
	// record should be shed by the governor.
	gov, err := collector.NewGovernor(collector.GovernorConfig{
		Clock:        clk,
		RatePerSec:   0.0001,
		BurstSize:    1,
		ShedInterval: time.Second,
	})
	if err != nil {
		t.Fatalf("NewGovernor: %v", err)
	}

	src := &fakeSource{}
	sink := &fakeSink{}
	p := NewPump(PumpConfig{
		Source:      src,
		Sink:        sink,
		Enricher:    enricher,
		Governor:    gov,
		Clock:       clk,
		HeadsLogDir: t.TempDir(),
	})

	src.records = [][]byte{
		buildForkRecord(100, 1, 42, 111, 222),
		buildForkRecord(101, 1, 42, 333, 444),
		buildForkRecord(102, 1, 42, 555, 666),
	}

	if _, err := p.Drain(); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	sent := sink.Sent()
	// Exactly one fork admitted (burst=1); the other two shed by the
	// governor and never turned into frames.
	if len(sent) != 1 {
		t.Fatalf("sent frames = %d, want 1 (governor should shed the rest)", len(sent))
	}

	gaps := p.FlushGaps()
	if len(gaps) != 1 {
		t.Fatalf("FlushGaps() = %d gap frames, want 1", len(gaps))
	}
	gapEv, ok := gaps[0].(*wire.Ev)
	if !ok {
		t.Fatalf("gap frame type = %T, want *wire.Ev", gaps[0])
	}
	if len(gapEv.Event) == 0 {
		t.Fatal("gap Ev frame has empty Event bytes")
	}
}

func TestPump_ReconnectEmitsDaemonRestartGap(t *testing.T) {
	clk := newFakeClock(time.Unix(2000, 0))
	p, _, sink := newTestPump(t, clk, 42, "sess1")

	clk.Advance(5 * time.Second)
	gapFrame, err := p.ReconnectGap("sess1")
	if err != nil {
		t.Fatalf("ReconnectGap: %v", err)
	}
	if err := p.Sink().Send(gapFrame); err != nil {
		t.Fatalf("Send gap frame: %v", err)
	}

	sent := sink.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent frames = %d, want 1", len(sent))
	}
	ev, ok := sent[0].(*wire.Ev)
	if !ok {
		t.Fatalf("sent[0] = %T, want *wire.Ev", sent[0])
	}
	if len(ev.Event) == 0 {
		t.Fatal("daemon_restart gap frame has empty Event bytes")
	}
}

func TestPump_HeadFrameAppendsToHeadsLog(t *testing.T) {
	clk := newFakeClock(time.Unix(3000, 0))
	p, _, sink := newTestPump(t, clk, 42, "sess1")

	want := wire.HeadReport{
		SessionID: "sess1",
		SegLast:   7,
		ChainHead: [32]byte{1, 2, 3},
		CkptHash:  [32]byte{4, 5, 6},
		At:        123456789,
	}
	sink.inbound = []wire.Frame{&wire.Head{Report: want}}

	n, err := p.PumpInbound()
	if err != nil {
		t.Fatalf("PumpInbound: %v", err)
	}
	if n != 1 {
		t.Fatalf("PumpInbound processed = %d, want 1", n)
	}

	heads, err := chain.ReadHeads(p.HeadsLogPath())
	if err != nil {
		t.Fatalf("ReadHeads: %v", err)
	}
	if len(heads) != 1 {
		t.Fatalf("heads.log has %d entries, want 1", len(heads))
	}
	got := heads[0]
	if got.SessionID != want.SessionID || got.SegLast != want.SegLast ||
		got.ChainHead != want.ChainHead || got.CkptHash != want.CkptHash || got.At != want.At {
		t.Fatalf("appended head = %+v, want %+v", got, want)
	}
}

func TestPump_HeadsLogNeverTruncatesAcrossReconnects(t *testing.T) {
	dir := t.TempDir()
	clk := newFakeClock(time.Unix(4000, 0))

	mkPump := func() (*Pump, *fakeSink) {
		pipeline, err := redact.NewPipeline([]byte("test-salt-0123456789"))
		if err != nil {
			t.Fatalf("redact.NewPipeline: %v", err)
		}
		enricher := collector.NewEnricher(collector.EnricherConfig{
			Pipeline: pipeline,
			DNSCache: collector.NewDNSCache(clk),
			Clock:    clk,
		})
		gov, err := collector.NewGovernor(collector.GovernorConfig{
			Clock: clk, RatePerSec: 1000, BurstSize: 1000, ShedInterval: time.Second,
		})
		if err != nil {
			t.Fatalf("NewGovernor: %v", err)
		}
		sink := &fakeSink{}
		p := NewPump(PumpConfig{
			Source: &fakeSource{}, Sink: sink, Enricher: enricher,
			Governor: gov, Clock: clk, HeadsLogDir: dir,
		})
		return p, sink
	}

	p1, sink1 := mkPump()
	sink1.inbound = []wire.Frame{&wire.Head{Report: wire.HeadReport{SessionID: "s", SegLast: 1, At: 1}}}
	if _, err := p1.PumpInbound(); err != nil {
		t.Fatalf("PumpInbound 1: %v", err)
	}

	// Simulate a daemon restart: a fresh Pump instance against the same
	// heads.log directory.
	p2, sink2 := mkPump()
	sink2.inbound = []wire.Frame{&wire.Head{Report: wire.HeadReport{SessionID: "s", SegLast: 2, At: 2}}}
	if _, err := p2.PumpInbound(); err != nil {
		t.Fatalf("PumpInbound 2: %v", err)
	}

	heads, err := chain.ReadHeads(p2.HeadsLogPath())
	if err != nil {
		t.Fatalf("ReadHeads: %v", err)
	}
	if len(heads) != 2 {
		t.Fatalf("heads.log has %d entries after reconnect, want 2 (must never truncate)", len(heads))
	}
	if heads[0].SegLast != 1 || heads[1].SegLast != 2 {
		t.Fatalf("heads.log entries out of order/lost: %+v", heads)
	}
}

func TestPump_SourceErrorPropagatesFromDrain(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p, src, _ := newTestPump(t, clk, 42, "sess1")
	src.records = [][]byte{buildForkRecord(1, 1, 42, 1, 1)}
	src.closed = true // Next() will now return errSourceClosed immediately

	_, err := p.Drain()
	if !errors.Is(err, errSourceClosed) {
		t.Fatalf("Drain err = %v, want wrapping errSourceClosed", err)
	}
}

func TestPump_SinkSendErrorPropagatesFromDrain(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p, src, sink := newTestPump(t, clk, 42, "sess1")
	src.records = [][]byte{buildForkRecord(1, 1, 42, 1, 1)}
	sink.sendErr = errors.New("boom")

	_, err := p.Drain()
	if err == nil {
		t.Fatal("Drain err = nil, want propagated send error")
	}
}

func TestHeadsLogPath_UnderHeadsLogDir(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p, _, _ := newTestPump(t, clk, 42, "sess1")
	got := p.HeadsLogPath()
	want := filepath.Join(p.headsLogDir, "heads.log")
	if got != want {
		t.Fatalf("HeadsLogPath() = %q, want %q", got, want)
	}
}

// TestFrameRoundTripsThroughRealWire proves the pump's Ev frames are
// well-formed wire.Ev frames that survive an actual wire.WriteFrame/
// wire.ReadFrame round trip (not just a fakeSink echo), catching any
// accidental payload corruption on the way to the frame.
func TestFrameRoundTripsThroughRealWire(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	p, src, sink := newTestPump(t, clk, 42, "sess1")
	src.records = [][]byte{buildForkRecord(1, 1, 42, 1, 1)}

	if _, err := p.Drain(); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	sent := sink.Sent()
	if len(sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(sent))
	}

	var buf bytes.Buffer
	if err := wire.WriteFrame(&buf, sent[0]); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := wire.ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if _, ok := got.(*wire.Ev); !ok {
		t.Fatalf("round-tripped frame type = %T, want *wire.Ev", got)
	}
}

// TestHeadsLogDirMustExist documents that AppendHead (and therefore the
// pump's PumpInbound) does not create parent directories — HeadsLogDir must
// already exist (ranad's setup path creates the root-owned data dir before
// the pump starts). A nonexistent parent surfaces as an error, not a silent
// drop of the head report.
func TestHeadsLogDirMustExist(t *testing.T) {
	clk := newFakeClock(time.Unix(1000, 0))
	pipeline, _ := redact.NewPipeline([]byte("test-salt-0123456789"))
	enricher := collector.NewEnricher(collector.EnricherConfig{
		Pipeline: pipeline, DNSCache: collector.NewDNSCache(clk), Clock: clk,
	})
	gov, _ := collector.NewGovernor(collector.GovernorConfig{
		Clock: clk, RatePerSec: 1000, BurstSize: 1000, ShedInterval: time.Second,
	})
	sink := &fakeSink{inbound: []wire.Frame{&wire.Head{Report: wire.HeadReport{SessionID: "s", At: 1}}}}
	p := NewPump(PumpConfig{
		Source: &fakeSource{}, Sink: sink, Enricher: enricher, Governor: gov, Clock: clk,
		HeadsLogDir: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if _, err := p.PumpInbound(); err == nil {
		t.Fatal("PumpInbound err = nil, want error for missing HeadsLogDir")
	}
	if _, err := os.Stat(p.HeadsLogPath()); err == nil {
		t.Fatal("heads.log should not have been created under a missing directory")
	}
}
