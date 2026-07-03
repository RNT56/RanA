//go:build linux

// This file requires github.com/godbus/dbus/v5, which CONTRACTS
// §internal/session whitelists as an importable dependency for
// linux-tagged files but which is NOT currently present in go.mod's
// require block (only golang.org/x/sys is available to non-cgo linux
// files today). Per the build rules for this package ("no go.mod edits"),
// this file is written to the intended final shape but will not compile
// with `go build`/`go vet` until a future commit adds:
//
//	require github.com/godbus/dbus/v5 vX.Y.Z
//
// to go.mod (plus the corresponding go.sum entries). See the final report
// for this package for the full flag. Until that lands, GOOS=linux builds
// of this package will fail on this file specifically; every other file
// in the package (including cgroup_linux.go, the raw-cgroupfs fallback
// driver that CONTRACTS names as the systemd alternative) compiles and
// vets clean for linux today.
package session

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"
)

// systemdProperty mirrors the (name, value) pairs StartTransientUnit
// expects, kept as a tiny local type so this file does not need to import
// dbus's higher-level systemd1 bindings (none are in the allowed
// dependency list — only the raw godbus/dbus/v5 client is).
type systemdProperty struct {
	Name  string
	Value dbus.Variant
}

// SystemdDriver is the primary Driver implementation on hosts where
// systemd is present (plan §6.1, docs/ARCHITECTURE.md §3): it creates
// session scopes as systemd transient units via the private D-Bus
// StartTransientUnit call, so `systemctl status rana-<id>.scope` and
// friends work naturally, and cleanup follows normal systemd scope
// lifecycle (stopping when empty, per WatchEmpty's cgroup.events fallback
// below for cases where the caller wants an explicit signal RanA itself
// observes rather than relying on systemd's own accounting).
//
// SystemdDriver talks to the system bus. It requires privileges
// equivalent to what ranad/rana already run with for cgroup management
// (CAP_SYS_ADMIN-adjacent via the systemd manager's Manage* actions, or
// equivalent polkit grant); it performs no privilege escalation itself.
type SystemdDriver struct {
	// Root overrides the cgroup v2 mount point used for reading
	// cgroup.events once systemd has placed the scope (systemd creates
	// scopes under Root/rana.slice/<name>.scope just like the raw
	// driver would); defaults to "/sys/fs/cgroup" when empty. Tests set
	// this to a t.TempDir()-backed mirror.
	Root string

	// conn is the D-Bus system bus connection; created lazily by
	// connect() and cached. Exposed as a field (rather than dialed fresh
	// per call) mirrors typical godbus usage and lets tests inject a
	// pre-connected fake bus in future work if needed.
	conn *dbus.Conn
}

var _ Driver = (*SystemdDriver)(nil)

const systemdBusName = "org.freedesktop.systemd1"
const systemdObjectPath = dbus.ObjectPath("/org/freedesktop/systemd1")

func (d *SystemdDriver) connect() (*dbus.Conn, error) {
	if d.conn != nil {
		return d.conn, nil
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, fmt.Errorf("session: connect system bus: %w", err)
	}
	d.conn = conn
	return conn, nil
}

// CreateScope implements Driver by calling
// org.freedesktop.systemd1.Manager.StartTransientUnit with mode "fail"
// (do not queue/replace a conflicting job — a name collision should
// surface as an error, mirroring CgroupDriver's ErrScopeExists), placing
// the new scope in rana.slice (property Slice=rana.slice) and starting it
// empty (PIDs are added afterward via AddProcess, since callers create the
// scope, then exec/migrate the process into it, or `rana run` seeds it
// with the freshly forked child).
func (d *SystemdDriver) CreateScope(ctx context.Context, name string) (Scope, error) {
	conn, err := d.connect()
	if err != nil {
		return Scope{}, err
	}

	unitName := name + ".scope"
	obj := conn.Object(systemdBusName, systemdObjectPath)

	props := []systemdProperty{
		{Name: "Slice", Value: dbus.MakeVariant(SliceName())},
		{Name: "Description", Value: dbus.MakeVariant("RanA session scope " + name)},
	}

	var jobPath dbus.ObjectPath
	call := obj.CallWithContext(ctx, systemdBusName+".Manager.StartTransientUnit", 0,
		unitName, "fail", props, []systemdProperty{})
	if err := call.Store(&jobPath); err != nil {
		if isUnitExistsError(err) {
			return Scope{}, ErrScopeExists
		}
		return Scope{}, fmt.Errorf("session: StartTransientUnit %s: %w", unitName, err)
	}

	return Scope{Name: name}, nil
}

// isUnitExistsError reports whether a D-Bus error from StartTransientUnit
// indicates the unit already exists, as opposed to any other failure.
func isUnitExistsError(err error) bool {
	dbusErr, ok := err.(dbus.Error)
	if !ok {
		return false
	}
	return dbusErr.Name == "org.freedesktop.systemd1.UnitExists"
}

// AddProcess implements Driver. systemd transient scopes only accept their
// full PID set at creation via StartTransientUnit's PIDs property in the
// general case; for RanA's usage (attach one additional pid, e.g. a
// --pid-migrated process, or a child exec'd after scope creation) the
// portable mechanism is the same cgroup.procs write CgroupDriver uses —
// systemd does not require going back through D-Bus for simple
// membership growth of an already-running scope, and this keeps
// AddProcess uniform across both drivers.
func (d *SystemdDriver) AddProcess(ctx context.Context, scopeName string, pid int32) error {
	cg := &CgroupDriver{Root: d.Root}
	return cg.AddProcess(ctx, scopeName, pid)
}

// DestroyScope implements Driver by asking systemd to stop the transient
// unit; systemd removes the cgroup once stopped.
func (d *SystemdDriver) DestroyScope(ctx context.Context, scopeName string) error {
	conn, err := d.connect()
	if err != nil {
		return err
	}

	unitName := scopeName + ".scope"
	obj := conn.Object(systemdBusName, systemdObjectPath)

	var jobPath dbus.ObjectPath
	call := obj.CallWithContext(ctx, systemdBusName+".Manager.StopUnit", 0, unitName, "fail")
	if err := call.Store(&jobPath); err != nil {
		if isUnitNotFoundError(err) {
			return ErrScopeNotFound
		}
		return fmt.Errorf("session: StopUnit %s: %w", unitName, err)
	}
	return nil
}

func isUnitNotFoundError(err error) bool {
	dbusErr, ok := err.(dbus.Error)
	if !ok {
		return false
	}
	return dbusErr.Name == "org.freedesktop.systemd1.NoSuchUnit"
}

// WatchEmpty implements Driver by delegating to the same cgroup.events
// inotify watch CgroupDriver uses: systemd places the scope's cgroup at
// the identical path (Root/rana.slice/<name>.scope), so RanA observes
// emptiness directly from the kernel rather than depending on systemd
// D-Bus signal subscriptions (fewer moving parts, and it means both
// drivers share one battle-tested watch implementation).
func (d *SystemdDriver) WatchEmpty(ctx context.Context, scopeName string) (<-chan struct{}, error) {
	cg := &CgroupDriver{Root: d.Root}
	return cg.WatchEmpty(ctx, scopeName)
}
