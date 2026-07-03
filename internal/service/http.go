package service

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/http"

	"github.com/RNT56/RanA/internal/ui"
)

// GenerateLaunchToken produces a fresh per-launch bearer token for the
// timeline HTTP host (docs/ARCHITECTURE.md §4: "per-launch bearer token").
// It is crypto/rand-derived so it cannot be guessed by another local,
// non-privileged process.
func GenerateLaunchToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("service: generating launch token: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// TimelineHostConfig configures a TimelineHost.
type TimelineHostConfig struct {
	// Token is the per-launch bearer token every route requires
	// (internal/ui.Handler enforces this). Required, non-empty.
	Token string
	// DataSource backs internal/ui's routes. Required.
	DataSource ui.DataSource
}

// TimelineHost wraps internal/ui.Handler with the config svc supplies.
// Binding a listener to 127.0.0.1:<random port> is the caller's
// responsibility (internal/ui deliberately never calls net.Listen, and
// neither does this type) — see Service.Start.
type TimelineHost struct {
	handler http.Handler
}

// NewTimelineHost builds a TimelineHost. It fails if cfg.Token is empty or
// cfg.DataSource is nil (internal/ui.Handler's own validation, surfaced
// here unchanged).
func NewTimelineHost(cfg TimelineHostConfig) (*TimelineHost, error) {
	h, err := ui.Handler(cfg.Token, cfg.DataSource)
	if err != nil {
		return nil, fmt.Errorf("service: building timeline handler: %w", err)
	}
	return &TimelineHost{handler: h}, nil
}

// Handler returns the http.Handler to mount on a 127.0.0.1-bound listener.
func (h *TimelineHost) Handler() http.Handler {
	return h.handler
}
