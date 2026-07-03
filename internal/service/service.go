// Package service implements RanA's user session service (svc,
// docs/ARCHITECTURE.md §2, CONTRACTS §internal/service): the user-owned
// process that assembles a ranad wire-frame server, a per-session marker
// socket, a content-digest worker, alert-rule wiring, and a localhost
// timeline HTTP host on top of an internal/ledger.Writer.
//
// svc is deliberately the top of the package graph: it imports and wires
// together internal/wire, internal/schema, internal/redact,
// internal/ledger, internal/profile, internal/alerts, and internal/ui, but
// nothing else in the tree imports svc. Every external dependency (clock,
// listener sockets, ledger directory, profile) is injectable so the whole
// package is testable on darwin against fakes: a fake ranad peer writing
// wire frames over a net.Pipe/UnixConn pair, and a fake agent writing
// newline-delimited JSON marker lines to a unix socket.
package service

import (
	"fmt"
	"net/http"
	"time"

	"github.com/RNT56/RanA/internal/alerts"
	"github.com/RNT56/RanA/internal/chain"
	"github.com/RNT56/RanA/internal/ledger"
	"github.com/RNT56/RanA/internal/profile"
	"github.com/RNT56/RanA/internal/redact"
	"github.com/RNT56/RanA/internal/schema"
)

// Clock abstracts wall-clock time for every timer-driven part of svc (the
// digest worker's mtime-scan ticker, per-launch token/session bookkeeping)
// so tests never sleep for real (CONTRACTS testing bar: injectable clocks
// everywhere time matters, no real sleeps >50ms).
type Clock interface {
	// Now returns the current wall-clock time.
	Now() time.Time
	// After returns a channel that receives the current time once d has
	// elapsed, mirroring time.After's shape so production code can use the
	// real clock unchanged.
	After(d time.Duration) <-chan time.Time
}

// systemClock is the production Clock backed by the real wall clock and
// real timers.
type systemClock struct{}

// SystemClock is the default production Clock.
var SystemClock Clock = systemClock{}

func (systemClock) Now() time.Time { return time.Now() }

func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Config configures a Service. Every field is either required or has a
// documented, safe zero-value behavior — see individual field docs.
type Config struct {
	// LedgerDir is the ledger.Datadir this Service reads/writes.
	// Required.
	LedgerDir ledger.Datadir
	// Key signs checkpoints (internal/chain.KeyInfo). Zero value means
	// segments seal but checkpoints are never signed — legal for tests,
	// never for production use (production callers load/generate a real
	// device key first, per internal/chain.GenerateKey/LoadKey).
	Key chain.KeyInfo
	// Profile is the active session's loaded profile (internal/profile),
	// supplying [markers], [digest], and redaction tightening. Required.
	Profile *profile.Profile
	// Session is this Service instance's session id. RanA runs one svc
	// wiring per active session's lifecycle in v1's model (CONTRACTS: the
	// marker socket and digest scopes are per-session).
	Session string
	// SessionCWD is the working directory $SESSION_CWD expands to in the
	// profile's digest scopes/excludes (docs/PROFILES.md).
	SessionCWD string
	// RedactionSalt is the per-ledger salt passed to redact.NewPipeline.
	// Required, non-empty (typically ledger.Datadir.LoadOrCreateSalt()).
	RedactionSalt []byte
	// Clock is used everywhere svc needs time. Defaults to SystemClock.
	Clock Clock
	// LaunchToken is the timeline HTTP host's per-launch bearer token.
	// Required, non-empty (typically GenerateLaunchToken()).
	LaunchToken string
	// MarkerSocket / MarkerToken configure the marker listener. Both empty
	// means "profile markers disabled or not wired" — StartMarkerListener
	// then returns ErrMarkersDisabled if the profile has markers enabled
	// but no socket/token was supplied (a caller error: NewSessionMarkerSocket
	// should have been called first).
	MarkerSocket string
	MarkerToken  string
	// RequireRanadUID, if non-nil, gates the ranad socket to this uid via
	// SO_PEERCRED (see RanadServerConfig.RequirePeerUID). Production
	// callers pass a pointer to rootUID; nil is used in tests connecting
	// over net.Pipe (which has no peer credential to check).
	RequireRanadUID *uint32
	// Notifier delivers best-effort desktop alert notifications. Defaults
	// to alerts.NopNotifier.
	Notifier alerts.Notifier
	// DigestDebounceInterval overrides DigestWorker's default debounce
	// ticker interval. Zero uses DigestWorker's own default.
	DigestDebounceInterval time.Duration
}

// ErrNilProfile is returned by NewService when cfg.Profile is nil.
var ErrNilProfile = fmt.Errorf("service: Config.Profile must not be nil")

// ErrEmptyLaunchToken is returned by NewService when cfg.LaunchToken is
// empty.
var ErrEmptyLaunchToken = fmt.Errorf("service: Config.LaunchToken must not be empty")

// Service assembles every piece CONTRACTS §internal/service describes: a
// ranad wire-frame server, an optional marker listener, an optional digest
// worker, alert-rule wiring, and a localhost timeline HTTP host, all on top
// of one internal/ledger.Writer for cfg.LedgerDir. Every dependency is
// injected via Config so the whole assembly is testable on darwin against
// fakes (see service_test.go).
type Service struct {
	cfg      Config
	clock    Clock
	pipeline *redact.Pipeline

	writer *ledger.Writer
	ds     *LedgerDataSource

	ranadServer *RanadServer
	markerLn    *MarkerListener
	digest      *DigestWorker
	digestStop  chan struct{}

	alertEngine *alerts.Engine

	timelineHost *TimelineHost

	idx *idxAllocator
}

// NewService constructs a Service: opens (or reuses) the ledger at
// cfg.LedgerDir, builds the redaction pipeline, the ledger-backed
// DataSource, the ranad wire server, the alert engine, and the timeline
// HTTP host. It does not start the marker listener or digest worker —
// those are optional and started explicitly (StartMarkerListener,
// StartDigestWorker) since not every profile/session needs them.
func NewService(cfg Config) (*Service, error) {
	if cfg.Profile == nil {
		return nil, ErrNilProfile
	}
	if cfg.LaunchToken == "" {
		return nil, ErrEmptyLaunchToken
	}
	if cfg.Clock == nil {
		cfg.Clock = SystemClock
	}

	pipeline, err := redact.NewPipeline(cfg.RedactionSalt, redactionOptionsFor(cfg.Profile)...)
	if err != nil {
		return nil, fmt.Errorf("service: building redaction pipeline: %w", err)
	}

	svc := &Service{
		cfg:      cfg,
		clock:    cfg.Clock,
		pipeline: pipeline,
		idx:      newIdxAllocator(),
	}

	writer, err := ledger.NewWriter(cfg.LedgerDir, ledger.WriterOptions{
		Key:          cfg.Key,
		OnHeadReport: svc.onHeadReport,
	})
	if err != nil {
		return nil, fmt.Errorf("service: opening ledger writer: %w", err)
	}
	svc.writer = writer

	ds, err := NewLedgerDataSource(cfg.LedgerDir)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("service: opening ledger data source: %w", err)
	}
	svc.ds = ds

	notifier := cfg.Notifier
	if notifier == nil {
		notifier = alerts.NopNotifier{}
	}
	engine, err := alerts.NewEngine(alerts.Config{
		Clock:    clockAdapter{svc.clock},
		Sink:     svc.appendAndPublish,
		Notifier: notifier,
	})
	if err != nil {
		writer.Close()
		ds.Close()
		return nil, fmt.Errorf("service: building alert engine: %w", err)
	}
	svc.alertEngine = engine

	svc.ranadServer = NewRanadServer(RanadServerConfig{
		Appender:       appenderFunc(svc.appendKernelEvent),
		RequirePeerUID: cfg.RequireRanadUID,
	})

	host, err := NewTimelineHost(TimelineHostConfig{Token: cfg.LaunchToken, DataSource: ds})
	if err != nil {
		writer.Close()
		ds.Close()
		return nil, fmt.Errorf("service: building timeline host: %w", err)
	}
	svc.timelineHost = host

	return svc, nil
}

// clockAdapter adapts a service.Clock to alerts.Clock (Now() time.Time
// only — alerts.Engine never needs After()).
type clockAdapter struct{ c Clock }

func (a clockAdapter) Now() time.Time { return a.c.Now() }

// appendEncodedAndPublish is appendAndPublish for kernel events arriving over
// the wire: it persists the canonical bytes verbatim (no re-encode — see
// ledger.Writer.AppendEncoded) and republishes to the live tail.
func (s *Service) appendEncodedAndPublish(ev schema.Event, enc []byte) error {
	if err := s.writer.AppendEncoded(ev, enc); err != nil {
		return err
	}
	s.ds.PublishLive(ev)
	return nil
}

// appenderFunc adapts a plain func to the Appender
// interface RanadServer expects.
type appenderFunc func(ev schema.Event, enc []byte) error

func (f appenderFunc) AppendEncoded(ev schema.Event, enc []byte) error { return f(ev, enc) }

// redactionOptionsFor builds the redact.Option set implied by a profile's
// [redaction] table (docs/PROFILES.md: extra patterns are additive,
// entropy thresholds may only tighten — both already enforced by
// redact.WithExtraPatterns/WithStricterEntropy, so this is pure
// translation). A profile with EntropyMinLen/EntropyThreshold both zero
// (the documented "unset" sentinel, see profile.Redaction's doc comment)
// contributes no WithStricterEntropy option.
func redactionOptionsFor(p *profile.Profile) []redact.Option {
	var opts []redact.Option
	if len(p.Redaction.ExtraPatterns) > 0 {
		opts = append(opts, redact.WithExtraPatterns(p.Redaction.ExtraPatterns))
	}
	if p.Redaction.EntropyMinLen != 0 || p.Redaction.EntropyThreshold != 0 {
		opts = append(opts, redact.WithStricterEntropy(p.Redaction.EntropyMinLen, p.Redaction.EntropyThreshold))
	}
	return opts
}

// Writer returns the underlying ledger.Writer, exposed for callers (cmd/
// entry points, tests) that need direct access for session lifecycle
// events (session.start/session.end) or explicit seal/flush control.
func (s *Service) Writer() *ledger.Writer { return s.writer }

// DataSource returns the ledger-backed ui.DataSource, exposed for tests
// and for callers that want to read the ledger through the same interface
// the timeline UI uses.
func (s *Service) DataSource() *LedgerDataSource { return s.ds }

// RanadHandler returns the ranad wire-frame connection handler, exposed so
// a caller can accept connections on its own listener (production) or feed
// it directly (tests).
func (s *Service) RanadHandler() *RanadServer { return s.ranadServer }

// TimelineHandler returns the localhost timeline HTTP handler. Binding
// 127.0.0.1:<port> is the caller's job.
func (s *Service) TimelineHandler() http.Handler {
	return s.timelineHost.Handler()
}

// appendAndPublish appends ev to the ledger and republishes it to the
// DataSource's live tail (used as both the alerts.Engine Sink and the
// general internal event-emission path for svc-originated events: markers,
// digest settles, session lifecycle).
func (s *Service) appendAndPublish(ev schema.Event) error {
	if err := s.writer.Append(ev); err != nil {
		return err
	}
	s.ds.PublishLive(ev)
	return nil
}

// appendKernelEvent is the Appender callback wired to RanadServer: every
// kernel-origin event from ranad is persisted, published to the live tail,
// AND observed by the alert engine (post-persist, per
// alerts.Engine.Observe's contract).
func (s *Service) appendKernelEvent(ev schema.Event, enc []byte) error {
	if err := s.appendEncodedAndPublish(ev, enc); err != nil {
		return err
	}
	return s.alertEngine.Observe(ev, ev.Seg)
}

// onHeadReport is the ledger.Writer's HeadReportFunc: it mirrors every
// checkpoint head to the currently-connected ranad peer(s)
// (docs/TRUST.md §5, plan D27).
func (s *Service) onHeadReport(r chain.HeadReport) {
	s.ranadServer.Broadcast(r)
}

// nextIdx allocates the next svc-owned Idx for session (see idx.go for why
// svc keeps its own namespace separate from ranad's).
func (s *Service) nextIdx(session string) uint64 {
	return s.idx.allocate(session)
}

// Close shuts down every started component and releases the ledger
// writer/data source. Idempotent-enough for test cleanup (double-Close on
// an already-closed writer/listener returns an error from that component,
// which Close aggregates but does not panic on).
func (s *Service) Close() error {
	if s.digestStop != nil {
		close(s.digestStop)
		s.digestStop = nil
	}
	if s.markerLn != nil {
		_ = s.markerLn.Close()
	}
	var firstErr error
	if s.ds != nil {
		if err := s.ds.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.writer != nil {
		if err := s.writer.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
