# Multi-user ranad (system-wide deployment)

RanA v1 ships **single-user by default** (D10): one `ranad` talks to one
session service (`svc`). This document specifies how one *system-wide, root*
`ranad` records **several users'** agent sessions at once, and what part of it
is built vs. what remains a Linux-host integration step.

The security bar is absolute: **one user's events must never reach another
user's `svc` or ledger.** The design achieves that by construction, not by
convention.

---

## 1. Single-user default (unchanged)

`rana run` (as the user) hosts an in-process `svc` that listens on a socket in
the user's runtime dir; a `ranad` dials it, `SO_PEERCRED`-gated (D10, v1.2). One
`ranad`, one `svc`, one ledger — the common case, and what CI exercises.

## 2. The routing seam (built)

The per-event send path routes through an `EventRouter` (`cmd/ranad/router.go`)
keyed by the **owner uid** of the event's session:

- `SingleUserRouter` returns the one sink for every uid — the default, so
  single-user behavior is byte-for-byte unchanged.
- `MultiUserRouter` maps each uid to that user's `svc` connection. `SinkFor` for
  an unregistered uid returns `ok=false` — the event is dropped, **never**
  routed to a different uid's sink. This is the cross-user isolation guarantee,
  unit-tested (`router_test.go`, including `-race`).

The pump learns each session's owner uid from the first `exec` record's `Uid`
(`Pump.noteSessionUID`) and routes every subsequent event for that session
accordingly.

## 3. Deployment model (decided)

A system-wide `ranad` runs as **root** under systemd (a *system* unit, not the
per-user unit), and:

1. **Attribution.** Every session is a cgroup-v2 scope under `rana.slice`
   (`internal/session`). The scope is created by the user's `rana run`, so the
   scope — and therefore every event's cgid — is owned by that user's uid.
   `ranad` resolves cgid → session → owner uid (kernel truth, P1).

2. **Per-user svc discovery.** Each user's `svc` creates its socket at a
   **registry path** `/run/rana/svc/<uid>.sock`, mode `0600`, owned by that uid
   (the containing dir is root-owned, `0711`, so a user can create only their
   own `<uid>.sock` and cannot see or connect to another's). `ranad` watches
   the registry directory (inotify), and for each `<uid>.sock`:
   - stats the socket and requires its **filesystem owner uid == the uid in the
     filename** (`socketOwnerUID`, the existing check), rejecting a mismatch;
   - dials it and performs the `Hello` handshake;
   - **`SO_PEERCRED`-validates** that the peer's uid equals that same uid;
   - registers the connection in the `MultiUserRouter` under that uid.
   A dropped connection unregisters the uid (its events then drop-with-account
   until it reconnects — see §4).

3. **Root-owned mirror stays global.** The D27 `heads.log` mirror remains
   root-owned and single, spanning all users' checkpoints — a user cannot
   suppress another user's head reports.

`ranad` still **only ever dials** (never listens), so it exposes no socket for a
malicious user to connect to — the same posture as single-user, extended to N
sockets it discovers and owner-validates.

## 4. Loss accounting (P5) for a not-yet-connected user

If an event arrives for a session whose owner has no connected `svc` (the user
hasn't started theirs, or it crashed), the pump drops it non-fatally
(`errNoSinkForOwner`) rather than misdeliver it. The system-wide daemon MUST
account this as a gap for that session — the intended mechanic is
**connect-before-route** (a session's cgroup can't be created without that
user's `rana`, which creates the registry socket first), with a bounded
buffer for the reconnect window. Wiring that accounting is part of the
integration step below.

## 5. What's built vs. what remains

| Piece | Status |
|---|---|
| `EventRouter` seam + `SingleUserRouter`/`MultiUserRouter` | **Built + unit-tested** (`router.go`, `router_test.go`) |
| Pump routes per-event by session owner uid | **Built** (single-user unchanged; verified by existing tests) |
| Session → owner-uid learning from `exec.Uid` | **Built** |
| Cross-user isolation (never fall back to another uid) | **Built + tested** |
| Per-user socket registry watch + owner-validated multi-dial loop | **Integration step** — belongs in `cmd/ranad/main_linux.go`; needs a real multi-user Linux host to verify |
| System-wide systemd unit + `/run/rana/svc` tmpfiles | **Integration step** |
| Real 2-user end-to-end + isolation test in CI | **Integration step** (the LTS-kernel CI matrix) |

The routing *logic and its isolation guarantee are complete and tested here*;
the multi-connection daemon loop and its real-host verification are the same
class of "needs a live Linux host" work as the eBPF attach (`LIMITS.md §8`), and
are gated behind that, not invented untested.
