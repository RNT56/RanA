//go:build linux && rana_bpf_generated

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/RNT56/RanA/internal/bpf"
)

// ringbufSource adapts bpf.Loader's rana_events ring buffer to the pump's
// RecordSource contract. Next() is non-blocking: it drains records already
// buffered in the kernel ring and returns ok=false the moment the ring is
// momentarily empty, matching the outbound loop's 50ms poll cadence (a
// blocking Read would stall FlushGaps/DrainEndedSessions between records).
// Non-blocking is achieved with a zero read deadline — the reader returns
// os.ErrDeadlineExceeded instead of waiting when no record is ready.
type ringbufSource struct {
	reader *ringbuf.Reader
}

func (s *ringbufSource) Next() (raw []byte, ok bool, err error) {
	// A deadline in the (very near) past makes Read return immediately:
	// with buffered records it yields the next one; with none it returns
	// ErrDeadlineExceeded, which we map to "nothing right now" (ok=false).
	s.reader.SetDeadline(time.Now())
	rec, rerr := s.reader.Read()
	if rerr != nil {
		if errors.Is(rerr, os.ErrDeadlineExceeded) {
			return nil, false, nil // ring momentarily empty
		}
		if errors.Is(rerr, ringbuf.ErrClosed) {
			return nil, false, nil // reader closed on shutdown; drain ends cleanly
		}
		return nil, false, fmt.Errorf("ringbuf read: %w", rerr)
	}
	// RawSample is a freshly-allocated slice per Read (cilium/ebpf default),
	// so handing it to the synchronous decoder is safe.
	return rec.RawSample, true, nil
}

// newRecordSource loads and attaches every eBPF program group via
// bpf.NewLoader (the harness-proven path), returns a ringbuf-backed
// RecordSource over rana_events, and hands the loader back as the pump's
// SessionRegistrar (RegisterSession/UnregisterSession write the kernel
// filter map). The returned close func detaches every program and closes
// the ring reader. A restart GapDescriptor (pins left by a previous ranad)
// is logged here; the per-connection ReconnectGap serveConnection already
// emits covers the persisted P5 gap on every (re)connect.
func newRecordSource() (RecordSource, SessionRegistrar, func(), error) {
	loader, gap, err := bpf.NewLoader(bpf.AttachOptions{})
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("ranad: loading eBPF collector: %w", err)
	}
	if gap != nil {
		log.Printf("ranad: eBPF collector re-attached over prior pins (a previous ranad ran); the reconnect gap covers the recording window it left")
	}
	if deg := loader.LSMDegraded(); deg != "" {
		// Optional coverage degraded, never fatal — but loud (P10).
		log.Printf("ranad: NOTE optional lsm/socket_connect hook inactive: %s", deg)
	}
	log.Printf("ranad: eBPF collector attached at tier %v", loader.Tier())

	src := &ringbufSource{reader: loader.Events()}
	closeFn := func() { _ = loader.Close() }
	return src, loader, closeFn, nil
}
