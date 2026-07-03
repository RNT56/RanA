package service

import (
	"github.com/RNT56/RanA/internal/alerts"
	"github.com/RNT56/RanA/internal/schema"
)

// AlertClock adapts a service Clock to alerts.Clock (alerts.Engine wants
// time.Time; service.Clock already exposes Now() time.Time, so the two
// shapes are structurally compatible without an adapter type — this file
// exists to document that compatibility and give the wiring a single named
// entry point, wireAlerts, rather than scattering alerts.NewEngine calls
// across service.go).

// AlertSink is the function shape alerts.Engine needs to persist a
// synthesized alert.* event; Service wires it directly to its
// ledger.Writer's Append (through the Appender interface, so it is
// testable against fakeAppender too).
type AlertSink = alerts.Sink

// wireAlerts constructs an alerts.Engine whose Sink both appends the
// synthesized alert.* event to the ledger AND republishes it to the
// DataSource's live tail (PublishLive) so the timeline sees new alerts
// without a page reload, mirroring how every other persisted event reaches
// the tail (see Service.appendAndPublish).
func wireAlerts(clock alerts.Clock, appendAndPublish func(schema.Event) error, notifier alerts.Notifier, opts ...alerts.Option) (*alerts.Engine, error) {
	return alerts.NewEngine(alerts.Config{
		Clock:    clock,
		Sink:     appendAndPublish,
		Notifier: notifier,
	}, opts...)
}
