//go:build linux

package main

// main_linux.go is ranad's real entry point: it locates (or generates) the
// redaction salt, constructs the portable Pump (pump.go) over a linux-only
// RecordSource/FrameSink pair, and runs the decode->enrich->redact->govern
// ->frame loop against the svc unix socket, emitting a gap{daemon_restart}
// frame on every (re)connect and mirroring every Head frame svc sends back
// into the root-owned heads.log (the D27 mirror write) — CONTRACTS §cmd/ranad.
//
// The eBPF attach itself (loading the bpf2go-generated CO-RE objects,
// opening the ring buffer) is NOT wired here yet: internal/bpf's
// loader_attach.go — the file that references the generated
// ranaExecObjects/loadRanaExecObjects/... symbols — is gated behind the
// `rana_bpf_generated` build tag, which is only set once `go generate
// ./internal/bpf` has produced those files (a Linux+clang CI step, per
// CONTRACTS §internal/bpf: "Compile-check happens in CI... never inside `go
// test`"). This checkout has not run that generation step, so there is no
// linux-buildable ringbuf-backed RecordSource to construct yet. Rather than
// invent one against symbols that don't exist, ranad's RecordSource here is
// ringbufSource: a real cilium/ebpf ringbuf.Reader wrapper whose
// construction is deferred to bpfLoader (see bpf_loader_linux.go), which
// honestly reports ErrBPFNotGenerated until that generation step has run.
// Every other piece of the daemon — connection setup, the frame pump, the
// heads.log mirror, the reconnect/gap sequence — is real and runs today.
import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/RNT56/RanA/internal/collector"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/wire"
)

// Defaults per install/ranad.service: StateDirectory=rana ->
// /var/lib/rana (heads.log, D27); RuntimeDirectory=rana -> /run/rana (the
// SO_PEERCRED-gated unix socket to svc). Overridable via env for tests /
// non-systemd hosts, never via a flag that could be used to disable
// redaction or the mirror (P3: "There is NO flag that disables redaction").
const (
	defaultDataDir = "/var/lib/rana"
	defaultRunDir  = "/run/rana"
	defaultSockRel = "ranad.sock"
)

func main() {
	if err := run(); err != nil {
		log.Printf("ranad: fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	dataDir := envOr("RANA_DATA_DIR", defaultDataDir)
	runDir := envOr("RANA_RUN_DIR", defaultRunDir)
	sockPath := filepath.Join(runDir, defaultSockRel)

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return fmt.Errorf("ranad: creating data dir %s: %w", dataDir, err)
	}
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return fmt.Errorf("ranad: creating run dir %s: %w", runDir, err)
	}

	salt, err := loadOrCreateSalt(filepath.Join(dataDir, "salt"))
	if err != nil {
		return fmt.Errorf("ranad: salt: %w", err)
	}

	pipeline, err := redact.NewPipeline(salt)
	if err != nil {
		return fmt.Errorf("ranad: building redaction pipeline: %w", err)
	}

	clock := collector.SystemClock
	dnsCache := collector.NewDNSCache(clock)
	enricher := collector.NewEnricher(collector.EnricherConfig{
		Pipeline: pipeline,
		DNSCache: dnsCache,
		Clock:    clock,
	})

	governor, err := collector.NewGovernor(collector.GovernorConfig{
		Clock:        clock,
		RatePerSec:   20000,
		BurstSize:    20000,
		ShedInterval: 5 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("ranad: building governor: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	source, registrar, closeSource, err := newRecordSource()
	if err != nil {
		return fmt.Errorf("ranad: record source: %w", err)
	}
	defer closeSource()

	// The DNS cache accumulates one entry per distinct resolved address for
	// as long as ranad runs — Join already refuses expired entries on its
	// own, but nothing removes them, so without a periodic sweep a
	// long-lived daemon's cache grows without bound over the machine's
	// uptime (every address any recorded agent's DNS answers ever
	// mentioned). GC is independent of the svc connection lifecycle (a
	// disconnected ranad still decodes ring-buffer records and observes DNS
	// answers), so it runs on its own ticker tied to ctx rather than inside
	// daemonLoop's per-connection loop.
	go runDNSCacheGC(ctx, dnsCache, clock)

	return daemonLoop(ctx, daemonLoopConfig{
		SockPath:    sockPath,
		Source:      source,
		Registrar:   registrar,
		Enricher:    enricher,
		Governor:    governor,
		Clock:       clock,
		HeadsLogDir: dataDir,
		Salt:        salt,
	})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadOrCreateSalt reads the redaction salt from path, generating and
// persisting a fresh one (0600) on first run. The salt is never derived
// from environment (P3) and is read once at daemon start, never per-event.
func loadOrCreateSalt(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) == 0 {
			return nil, fmt.Errorf("ranad: salt file %s is empty", path)
		}
		return b, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("ranad: reading salt file %s: %w", path, err)
	}

	salt := make([]byte, 32)
	if _, err := randRead(salt); err != nil {
		return nil, fmt.Errorf("ranad: generating salt: %w", err)
	}
	if err := os.WriteFile(path, salt, 0o600); err != nil {
		return nil, fmt.Errorf("ranad: writing salt file %s: %w", path, err)
	}
	return salt, nil
}

// daemonLoopConfig bundles daemonLoop's dependencies so both main() and
// tests (in future, once a real bpf source exists) can construct it
// without a giant positional argument list.
type daemonLoopConfig struct {
	SockPath    string
	Source      RecordSource
	Registrar   SessionRegistrar // arms/disarms kernel capture per session; nil in an ungenerated build
	Enricher    *collector.Enricher
	Governor    *collector.Governor
	Clock       collector.Clock
	HeadsLogDir string
	Salt        []byte
}

// daemonLoop owns the connect/reconnect cycle to svc's unix socket: for
// each connection it performs the Hello handshake, checks SO_PEERCRED
// against the connecting uid, sends a gap{daemon_restart} frame ("on
// reconnect emit gap{daemon_restart}", CONTRACTS §cmd/ranad), then hands
// the connection to Pump.Drain/PumpInbound until the connection breaks, at
// which point it retries. It exits cleanly when ctx is cancelled.
func daemonLoop(ctx context.Context, cfg daemonLoopConfig) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		if ctx.Err() != nil {
			return nil
		}

		conn, err := dialSVC(ctx, cfg.SockPath)
		if err != nil {
			log.Printf("ranad: dial svc socket %s: %v (retrying in %s)", cfg.SockPath, err, backoff)
			if !sleepCtx(ctx, backoff) {
				return nil
			}
			backoff = nextBackoff(backoff, maxBackoff)
			continue
		}
		backoff = time.Second

		if err := serveConnection(ctx, conn, cfg); err != nil {
			log.Printf("ranad: connection to svc ended: %v", err)
		}
	}
}

// dnsCacheGCInterval is how often runDNSCacheGC sweeps expired entries out
// of the DNS cache. Independent of any per-session or per-connection
// cadence — DNS answers are observed and joined regardless of which
// session's ring-buffer records are currently flowing.
const dnsCacheGCInterval = 5 * time.Minute

// runDNSCacheGC periodically sweeps cache of TTL-expired entries until ctx
// is cancelled, bounding the cache's memory footprint over a long-lived
// daemon's uptime (collector.DNSCache.GC's doc comment: "Join already
// refuses expired entries on its own, so GC is a cleanliness/memory
// concern, not a correctness one" — but a concern that must actually be
// acted on for a daemon that outlives many sessions and resolves many
// distinct addresses).
func runDNSCacheGC(ctx context.Context, cache *collector.DNSCache, clock collector.Clock) {
	ticker := time.NewTicker(dnsCacheGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cache.GC(clock.Now())
		}
	}
}

func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		return max
	}
	return next
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// dialSVC connects to svc's SO_PEERCRED-gated unix socket and performs the
// Hello handshake (role=ranad). It does not listen — ranad only ever
// dials out to svc's socket (CONTRACTS: "NO listening TCP"; the daemon
// holds no listening socket of any kind, matching install/ranad.service's
// RestrictAddressFamilies=AF_UNIX AF_NETLINK).
func dialSVC(ctx context.Context, path string) (*net.UnixConn, error) {
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		c.Close()
		return nil, fmt.Errorf("ranad: dialed connection is not a *net.UnixConn (%T)", c)
	}
	return uc, nil
}

// socketOwnerUID returns the uid that owns the filesystem entry at path
// (the svc unix socket ranad just dialed). Used by serveConnection to
// verify the connected peer's SO_PEERCRED uid actually matches whoever
// controls the socket path, rather than trusting any process that answers
// there. A best-effort, defense-in-depth check: like any path-based stat,
// it is not immune to the socket being replaced between dial and stat, but
// it closes the common case (a stale or foreign-owned listener already
// sitting at the path when ranad connects) that the pure Hello-handshake
// role check does not.
func socketOwnerUID(path string) (uint32, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("ranad: could not read owner uid of %s", path)
	}
	return st.Uid, nil
}

// serveConnection drives one connection's lifetime: Hello handshake,
// daemon_restart gap, then concurrently pumping outbound event frames and
// inbound Head frames until either direction errors.
//
// Before anything else, it verifies the peer's SO_PEERCRED uid matches the
// filesystem owner of the socket path ranad just dialed. ranad is the one
// side of this link that does not know its peer's expected uid ahead of
// time (svc's RequirePeerUID pins the reverse direction to root, but ranad
// dials a per-user path and must discover whose socket it's talking to);
// without this check, any local process that manages to have something
// listening at cfg.SockPath when ranad dials (a mis-owned/world-writable
// run-dir, a race during svc startup, a misconfigured RANA_RUN_DIR shared
// across users) would receive ranad's Hello (including the redaction salt)
// and every enriched kernel event ranad emits, and could feed forged Head
// frames into the root-owned heads.log mirror (the D27 mirror write) — silently
// defeating the same-uid tamper-evidence guarantee docs/THREAT-MODEL.md §3.2
// depends on. Comparing against the file's owning uid (not e.g. a fixed
// "non-root" assumption) keeps this correct for any recorded user.
func serveConnection(ctx context.Context, conn *net.UnixConn, cfg daemonLoopConfig) error {
	defer conn.Close()

	fileUID, statErr := socketOwnerUID(cfg.SockPath)
	if statErr != nil {
		return fmt.Errorf("ranad: stat svc socket %s: %w", cfg.SockPath, statErr)
	}
	peerUID, err := wire.PeerCred(conn)
	if err != nil {
		return fmt.Errorf("ranad: peer credential check failed: %w", err)
	}
	if peerUID != fileUID {
		return fmt.Errorf("ranad: rejecting svc connection: peer uid %d does not match socket owner uid %d", peerUID, fileUID)
	}

	if err := wire.WriteFrame(conn, &wire.Hello{V: wire.Version, Role: wire.RoleRanad, Salt: cfg.Salt}); err != nil {
		return fmt.Errorf("ranad: sending Hello: %w", err)
	}
	peerHello, err := wire.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("ranad: reading svc's Hello: %w", err)
	}
	hello, ok := peerHello.(*wire.Hello)
	if !ok || hello.Role != wire.RoleSVC {
		return fmt.Errorf("ranad: expected svc Hello, got %T", peerHello)
	}

	sink := newConnFrameSink(conn)
	pump := NewPump(PumpConfig{
		Source:      cfg.Source,
		Sink:        sink,
		Enricher:    cfg.Enricher,
		Governor:    cfg.Governor,
		Clock:       cfg.Clock,
		HeadsLogDir: cfg.HeadsLogDir,
		Registrar:   cfg.Registrar,
	})

	// P5: every (re)connect is itself a gap, and it must be recorded, not
	// just logged locally.
	gapFrame, err := pump.ReconnectGap("")
	if err == nil {
		if sendErr := sink.Send(gapFrame); sendErr != nil {
			return fmt.Errorf("ranad: sending reconnect gap: %w", sendErr)
		}
	} else {
		log.Printf("ranad: building reconnect gap frame: %v", err)
	}

	errCh := make(chan error, 2)
	go func() { errCh <- inboundLoop(ctx, pump) }()
	go func() { errCh <- outboundLoop(ctx, pump) }()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return nil
	}
}

// outboundLoop repeatedly drains available records and flushes governor
// gaps on a fixed tick, sending everything through the pump's Sink.
func outboundLoop(ctx context.Context, pump *Pump) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		if _, err := pump.Drain(); err != nil {
			return err
		}
		for _, f := range pump.FlushGaps() {
			if err := pump.Sink().Send(f); err != nil {
				return err
			}
		}
		// Release per-session collector state for sessions svc has reported
		// ended (via inbound SessionEnd frames); any final governor gap comes
		// back as a frame to send from this Send-owning goroutine.
		for _, f := range pump.DrainEndedSessions() {
			if err := pump.Sink().Send(f); err != nil {
				return err
			}
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		case <-time.After(50 * time.Millisecond):
			// Short poll interval when there is no ring-buffer blocking
			// read wired up yet (see the RecordSource note at the top of
			// this file); a real ringbuf.Reader read is itself blocking
			// and would replace this poll loop with a natural wakeup.
		}
	}
}

// inboundLoop repeatedly pumps Head frames from svc into heads.log.
func inboundLoop(ctx context.Context, pump *Pump) error {
	for {
		if _, err := pump.PumpInbound(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(50 * time.Millisecond):
		}
	}
}
