# Native macOS recording — design option (not shipped in v1)

RanA on macOS records **inside a Linux guest VM** and nothing that runs
natively (D2/D15, `docs/MACOS.md`). That is a deliberate v1 choice, not a dead
end. This document designs the *native* path so the architecture is not
permanently boxed into VM-only, and states exactly why it does not ship yet.

## Why VM-only today

Native process/file/network recording on macOS requires Apple's **Endpoint
Security** framework, which is gated behind the
`com.apple.developer.endpoint-security.client` entitlement. Apple grants that
entitlement **case-by-case, tied to a paid Developer account and a stated
distribution plan**, and it is effectively closed to open-source,
freely-redistributable binaries. A binary without the entitlement cannot call
`es_new_client` at all — it fails at runtime, not build time. So an OSS-first
tool cannot make native recording its default and still be `curl | sh`-
installable. The microVM is the honest path that works for everyone today.

## The seam (already latent in the architecture)

RanA's collector consumes a **platform-neutral event stream** (the frozen
event schema, `internal/schema`), and the ledger/redact/chain/UI layers never
know how events were captured. There are already two producers of that stream:
the Linux eBPF collector and the macOS *guest* (which is the same Linux
collector inside the VM). A native macOS producer is a **third source behind
the same seam** — it does not touch the trust core.

Concretely, introduce one interface (mirroring `cmd/ranad`'s `RecordSource`):

```
// EventSource yields already-attributed, pre-schema capture events for one
// host role. Implementations: eBPF (linux), guest-vsock (macOS VM), and —
// this document — endpoint-security (macOS native).
type EventSource interface { Next() (rawEvent, bool, error) }
```

The native implementation lives in a `//go:build darwin && cgo` file and never
compiles into the Linux build; the collector, redaction, and ledger are
imported unchanged.

## What a native ES source would capture (and not)

Endpoint Security is **not** a drop-in for eBPF; the honesty rules (P4/P10)
apply to the mapping:

| RanA event | ES source | Fidelity note |
|---|---|---|
| `proc.exec` / `fork` / `exit` | `ES_EVENT_TYPE_NOTIFY_EXEC` / `FORK` / `EXIT` | Full argv + exe path + audit-token uid — good parity. |
| `fs.write_open` / `unlink` / `rename` / … | `NOTIFY_OPEN` / `UNLINK` / `RENAME` / `SETMODE` / `TRUNCATE` | ES delivers a **resolved** path (`path_source=resolved`) — better than the syscall-arg fallback. |
| `fs.sensitive_read` | `NOTIFY_OPEN` filtered by the watchlist | Same watchlist model. |
| `net.connect` / `net.dns` | **Weak.** ES has no first-class outbound-connect event; the modern path is a `NEFilterDataProvider` **Network Extension** (a *separate* entitlement + a system-extension install), or fall back to no native network capture. | This is the biggest gap vs. eBPF's `cgroup/connect4·6`. Document it as a native blind spot. |
| attribution | `cgroup`-equivalent is absent on macOS; use the **audit token** (pid+pidversion) and the responsible-pid chain, scoped to the adopted process subtree. | No cgroup-v2 leaf; attribution is by process-tree, a documented weaker boundary. |

So a native ES path would give strong exec/file coverage, a resolved-path
advantage, **weaker network coverage**, and a process-tree (not cgroup)
attribution boundary — all of which `LIMITS.md` would state plainly.

## What it still requires (the gate)

1. The `com.apple.developer.endpoint-security.client` entitlement (Apple
   approval) — and, for native network capture, a Network Extension entitlement
   + system-extension activation (user-approved, MDM-friendly).
2. Developer-ID codesigning + notarization of the host binary and any
   system/endpoint extension.
3. A distribution story that isn't `curl | sh` (a signed, notarized installer),
   because an entitled binary can't be freely rebuilt-and-run by anyone.

## Decision

**v1 ships VM-only.** The native ES path is designed here as a *behind-the-seam
third `EventSource`*, so it can be added without disturbing the collector,
redaction, ledger, or verification — if and when the entitlement is obtained
and a signed-distribution channel exists. The architecture is therefore not
permanently limited to the VM; the limitation is Apple's entitlement policy,
stated honestly, with the extension point already shaped.
