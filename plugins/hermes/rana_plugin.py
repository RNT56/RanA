"""
RanA marker emitter for Hermes Agent (Nous Research).

Emits run-lifecycle MARKERS to the local RanA marker socket so the RanA
timeline can render "inbound message -> these execs -> these egress connects
-> this file changed" — clustering a run's kernel effects by runId.

WHAT IT SENDS (and NOTHING else): identifiers + lifecycle ONLY —
{ runId, agentId, channel, status, phase, ts }. It NEVER sends prompts,
completions, message text, or any model I/O (P7, RanA's #1 scope wall). The
sanitizer below drops everything outside the allowlist before it leaves this
process, and RanA's own marker listener rejects any line carrying a forbidden
field, so a bug here fails safe.

TRANSPORT: newline-delimited JSON over a Unix domain socket whose path + a
per-session token are provided by RanA via the RANA_MARKER_SOCKET /
RANA_MARKER_TOKEN environment variables. If RANA_MARKER_SOCKET is absent, the
plugin is completely INERT (no socket, no error) — RanA simply isn't present.

INSTALL: drop this file in ~/.hermes/plugins/ (see README.md). Hermes discovers
plugins there and calls register(context); this plugin registers hooks on the
run/session start and end lifecycle events. Because the exact hook names differ
across Hermes versions, register() is defensive and best-effort — the
protocol-critical core (send_marker / sanitize) is version-independent.
"""

import json
import os
import socket
import time

# The ONLY keys allowed to leave this process. Anything else is dropped.
ALLOWED_FIELDS = ("runId", "agentId", "channel", "status", "phase", "ts")

SOCKET_PATH = os.environ.get("RANA_MARKER_SOCKET") or None
SOCKET_TOKEN = os.environ.get("RANA_MARKER_TOKEN", "")

_CONNECT_TIMEOUT = 0.25  # seconds; a wedged socket must never linger


def _sanitize(fields):
    """Keep only allowlisted identifier/lifecycle fields; coerce to scalars."""
    out = {}
    for k in ALLOWED_FIELDS:
        if k in fields and fields[k] is not None:
            v = fields[k]
            if isinstance(v, (str, int, float, bool)):
                out[k] = v
            else:
                out[k] = str(v)
    return out


def send_marker(event, **fields):
    """
    Emit one marker. event is "run.start" or "run.end". Best-effort and
    crash-proof: any failure (RanA down, serialize error, wedged socket) is
    swallowed silently. One connection per marker keeps this stateless.
    """
    if not SOCKET_PATH:
        return  # inert when RanA isn't present
    try:
        payload = json.dumps(
            {
                "v": 1,
                "token": SOCKET_TOKEN,
                # The listener keys the marker.<event> type off the "event"
                # field (internal/service/marker.go), NOT "kind".
                "event": event,
                "origin": "enrichment",  # P1: markers are never authoritative
                **_sanitize(fields),
            },
            separators=(",", ":"),
        ) + "\n"
    except Exception:
        return  # if we can't even serialize identifiers, drop silently

    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(_CONNECT_TIMEOUT)
        sock.connect(SOCKET_PATH)
        sock.sendall(payload.encode("utf-8"))
    except Exception:
        pass  # swallow — markers are best-effort by design
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def _run_id(ctx):
    """Best-effort extraction of a stable per-run id from a Hermes event/ctx."""
    for attr in ("run_id", "runId", "session_id", "sessionId", "conversation_id"):
        v = getattr(ctx, attr, None) or (ctx.get(attr) if isinstance(ctx, dict) else None)
        if v:
            return str(v)
    return None


def _channel(ctx):
    for attr in ("channel", "surface", "source"):
        v = getattr(ctx, attr, None) or (ctx.get(attr) if isinstance(ctx, dict) else None)
        if v:
            return str(v)
    return None


def on_run_start(ctx=None):
    """Hook: a run/conversation began."""
    send_marker(
        "run.start",
        runId=_run_id(ctx),
        agentId="hermes",
        channel=_channel(ctx),
        status="accepted",
        phase="start",
        ts=int(time.time() * 1000),
    )


def on_run_end(ctx=None, status="completed"):
    """Hook: a run/conversation finished."""
    send_marker(
        "run.end",
        runId=_run_id(ctx),
        agentId="hermes",
        status=status,
        phase="end",
        ts=int(time.time() * 1000),
    )


def register(context):
    """
    Hermes plugin entry point. Hermes discovers plugins under ~/.hermes/plugins/
    and calls register(context); the context exposes a hook-registration API.
    Because hook names vary across Hermes versions, this tries the common ones
    and no-ops on whatever isn't present (never raises — a plugin must not break
    the agent). Adjust the event names below to your Hermes version's
    gateway/hooks.py lifecycle if they differ (see README.md).
    """
    if context is None:
        return

    # Prefer an explicit hook-registration method if the context exposes one.
    register_hook = getattr(context, "register_hook", None) or getattr(context, "add_hook", None)
    if callable(register_hook):
        for name in ("run_start", "session_start", "conversation_start", "on_run_start"):
            try:
                register_hook(name, on_run_start)
            except Exception:
                pass
        for name in ("run_end", "session_end", "conversation_end", "on_run_end"):
            try:
                register_hook(name, on_run_end)
            except Exception:
                pass
        return

    # Fallback: a generic event bus (context.on(event, handler)).
    on = getattr(context, "on", None)
    if callable(on):
        try:
            on("run.start", on_run_start)
            on("run.end", lambda c=None: on_run_end(c))
        except Exception:
            pass


# Manual smoke test: `python rana_plugin.py` sends a run.start/run.end pair to
# $RANA_MARKER_SOCKET (start a listener there first) so you can verify the wire
# format against a loopback socket without a running Hermes.
if __name__ == "__main__":
    on_run_start({"run_id": "smoke-0001", "channel": "cli"})
    on_run_end({"run_id": "smoke-0001"}, status="completed")
    print("sent run.start + run.end to", SOCKET_PATH or "(inert: RANA_MARKER_SOCKET unset)")
