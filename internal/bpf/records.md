# RanA BPF ring-buffer record layouts (v1)

This is the **canonical** byte-by-byte layout document for every fixed-size
record RanA's eBPF programs write into the ring buffer
(`BPF_MAP_TYPE_RINGBUF`) and that `internal/collector/records.go` decodes on
the userspace (`ranad`) side. The Go decoder is written **against this
document**; `internal/collector/records_test.go` cross-checks every
decoder's size/offset constants against the numbers declared here, so the
two cannot silently drift apart.

The authoritative C definitions live in `bpf/src/records.h` (owned by the
`internal/bpf` implementer) and MUST match this document exactly — that is
a cross-check for `internal/bpf`, not this package.

## Conventions

- **Byte order:** little-endian throughout (native order on all
  RanA-supported targets: x86_64, aarch64).
- **No padding:** every record is a flat sequence of fixed-width fields at
  explicit byte offsets, decoded field-by-field via `encoding/binary`. There
  is no implicit alignment padding anywhere in the wire format. Flattening
  away C-struct alignment before `bpf_ringbuf_output`/`bpf_ringbuf_reserve`
  is the `internal/bpf` implementer's responsibility.
- **Version byte:** every record's first byte is `Version uint8`. Decoders
  reject any version they do not recognize with `ErrUnsupportedVersion`. All
  kinds below are version `1`.
- **Kind byte:** every record's second byte is `Kind uint8`, one of the
  `RecordKind*` constants in `records.go`. A single ring buffer carries
  heterogeneous record kinds; `DecodeRecord` dispatches on this byte after
  validating `Version`.
- **Fixed-size, self-contained:** variable-length data (argv, paths,
  qnames) is carried in a fixed-capacity, length-prefixed byte array inside
  the record itself (never a pointer/slice elsewhere), so a record is safe
  to copy out of kernel memory in one shot. A `*Len` field gives the valid
  prefix length; truncation is explicit via a `Truncated` flag where it
  matters downstream (argv, DNS answers).
- **Strings:** raw bytes, NUL-padded to capacity; `*Len` gives the valid
  prefix length in bytes. The decoder never trusts bytes beyond `Len`, and
  never trusts `Len` beyond the field's capacity (a `Len` larger than
  capacity is a decode error, not a silent clamp — garbage must not panic,
  per the fuzz requirement, but it also must not be treated as valid).
- **Timestamps:** `TsMono`/`TsWall` are `uint64` nanoseconds captured
  in-kernel, matching `schema.Event.TsMono`/`TsWall` directly — no unit
  conversion in the collector.
- **cgid:** `uint64`, the cgroup id used for the in-kernel session filter
  map (D6); `Enricher` maps `cgid → session id` (portable, synthetic in
  tests — the real map is populated by `internal/bpf` from the session
  lifecycle).
- **Addresses:** `Daddr [16]byte` always; IPv4 addresses are v4-mapped
  (`::ffff:a.b.c.d`: bytes 0-9 zero, bytes 10-11 `0xff`, bytes 12-15 the v4
  octets), matching `schema.NewNetConnect`'s requirement that `daddr` MUST
  be 16 bytes. `Family uint8`: `4` = AF_INET, `6` = AF_INET6.

## Record kind registry

| Kind byte | Name | Go type | Size (bytes) |
|---|---|---|---|
| 1 | exec | `ExecRecord` | 8254 |
| 2 | fork | `ForkRecord` | 34 |
| 3 | exit | `ExitRecord` | 50 |
| 4 | fsop | `FsOpRecord` | 4148 |
| 5 | connect | `ConnectRecord` | 50 |
| 6 | sendmsg | `SendmsgRecord` | 50 |
| 7 | unixconnect | `UnixConnectRecord` | 4128 |
| 8 | flowclose | `FlowCloseRecord` | 74 |
| 9 | dns | `DNSRecord` | 356 |
| 10 | migration | `MigrationRecord` | 38 |

Every table below starts at offset 0 with the shared `Version`/`Kind`
header. Sizes and offsets in this document are the single source of truth;
`records.go`'s `Size*` and per-field offset constants are generated to match
exactly, and `TestRecordLayoutsMatchDoc` asserts the equality.

---

## 1. `ExecRecord` (kind=1, proc.exec) — 8254 bytes

Argv is capped at 6144 raw bytes (NUL-separated arguments); exe path and cwd
are each capped at 1024 bytes. All three caps are generous for real-world
paths/argv while keeping the record a bounded, fixed size.

| Offset | Field | Type | Notes |
|---|---|---|---|
| 0 | Version | uint8 | |
| 1 | Kind | uint8 | =1 |
| 2 | Pid | uint32 | |
| 6 | Ppid | uint32 | |
| 10 | Uid | uint32 | |
| 14 | Cgid | uint64 | |
| 22 | TsMono | uint64 | |
| 30 | TsWall | uint64 | |
| 38 | CommLen | uint8 | valid bytes in Comm, ≤16 |
| 39 | Comm | [16]byte | NUL-padded |
| 55 | ExePathLen | uint16 | valid bytes in ExePath, ≤1024 |
| 57 | ExePath | [1024]byte | NUL-padded |
| 1081 | CwdLen | uint16 | valid bytes in Cwd, ≤1024 |
| 1083 | Cwd | [1024]byte | NUL-padded |
| 2107 | ArgvLen | uint16 | valid bytes in Argv, ≤6144 |
| 2109 | ArgvTruncated | uint8 | 1 iff the true argv exceeded 6144 raw bytes |
| 2110 | Argv | [6144]byte | args NUL-separated, NUL-padded tail |
| **8254** | *(end)* | | total record size |

**Argv decoding:** split `Argv[:ArgvLen]` on `0x00`; a trailing empty token
(produced by a trailing NUL) is dropped. Each resulting token becomes one
element of the `argv []string` handed to `Enricher`, which redacts every
element via `Pipeline.RedactArgv` before it can reach `schema.NewProcExec`
(P3 — no raw argv byte reaches the ledger).

## 2. `ForkRecord` (kind=2, proc.fork) — 34 bytes

| Offset | Field | Type |
|---|---|---|
| 0 | Version | uint8 |
| 1 | Kind | uint8 |
| 2 | Pid | uint32 |
| 6 | Ppid | uint32 |
| 10 | Cgid | uint64 |
| 18 | TsMono | uint64 |
| 26 | TsWall | uint64 |
| **34** | *(end)* | total record size |

## 3. `ExitRecord` (kind=3, proc.exit) — 50 bytes

| Offset | Field | Type |
|---|---|---|
| 0 | Version | uint8 |
| 1 | Kind | uint8 |
| 2 | Pid | uint32 |
| 6 | Cgid | uint64 |
| 14 | TsMono | uint64 |
| 22 | TsWall | uint64 |
| 30 | ExitCode | int32 |
| 34 | UtimeNs | uint64 |
| 42 | StimeNs | uint64 |
| **50** | *(end)* | total record size |

## 4. `FsOpRecord` (kind=4) — 4148 bytes

One shared layout for every fs.* kernel event; the semantic sub-type is
carried in `Op uint8` (`FsOpWriteOpen`, `FsOpUnlink`, `FsOpRename`,
`FsOpMkdir`, `FsOpChmod`, `FsOpTruncate`). `Path2` is only meaningful for
`FsOpRename` (the destination path) and is zero-length (`Path2Len == 0`)
otherwise.

| Offset | Field | Type | Notes |
|---|---|---|---|
| 0 | Version | uint8 | |
| 1 | Kind | uint8 | =4 |
| 2 | Op | uint8 | `FsOp*` constant |
| 3 | PathSource | uint8 | 0=resolved, 1=claimed (D7) |
| 4 | Pid | uint32 | |
| 8 | Cgid | uint64 | |
| 16 | TsMono | uint64 | |
| 24 | TsWall | uint64 | |
| 32 | Flags | uint64 | O_WRONLY/O_RDWR/O_CREAT/O_TRUNC bitmask (write_open only; 0 otherwise) |
| 40 | Mode | uint64 | mode_t (mkdir/chmod) or target size (truncate); 0 for unlink/rename |
| 48 | PathLen | uint16 | valid bytes in Path, ≤2048 |
| 50 | Path | [2048]byte | NUL-padded |
| 2098 | Path2Len | uint16 | valid bytes in Path2, ≤2048; 0 unless Op==rename |
| 2100 | Path2 | [2048]byte | NUL-padded; rename destination only |
| **4148** | *(end)* | | total record size |

## 5. `ConnectRecord` (kind=5, net.connect via cgroup/connect4·6) — 50 bytes

| Offset | Field | Type | Notes |
|---|---|---|---|
| 0 | Version | uint8 | |
| 1 | Kind | uint8 | =5 |
| 2 | Proto | uint8 | 6=TCP, 17=UDP |
| 3 | Family | uint8 | 4 or 6 |
| 4 | Pid | uint32 | |
| 8 | Cgid | uint64 | |
| 16 | TsMono | uint64 | |
| 24 | TsWall | uint64 | |
| 32 | Daddr | [16]byte | v4-mapped for IPv4 |
| 48 | Dport | uint16 | |
| **50** | *(end)* | | total record size |

## 6. `SendmsgRecord` (kind=6, net.connect via cgroup/sendmsg4·6, unconnected UDP) — 50 bytes

Identical field layout to `ConnectRecord` — kept as a distinct `Kind` byte
so the collector can tell the two apart for governor accounting even though
both decode into the same `schema.EventTypeNetConnect` shape.

| Offset | Field | Type |
|---|---|---|
| 0 | Version | uint8 |
| 1 | Kind | uint8 |
| 2 | Proto | uint8 |
| 3 | Family | uint8 |
| 4 | Pid | uint32 |
| 8 | Cgid | uint64 |
| 16 | TsMono | uint64 |
| 24 | TsWall | uint64 |
| 32 | Daddr | [16]byte |
| 48 | Dport | uint16 |
| **50** | *(end)* | total record size |

## 7. `UnixConnectRecord` (kind=7, unix.connect via fentry unix_stream_connect) — 4128 bytes

| Offset | Field | Type | Notes |
|---|---|---|---|
| 0 | Version | uint8 | |
| 1 | Kind | uint8 | =7 |
| 2 | Pid | uint32 | |
| 6 | Cgid | uint64 | |
| 14 | TsMono | uint64 | |
| 22 | TsWall | uint64 | |
| 30 | PathLen | uint16 | valid bytes in Path, ≤4096 |
| 32 | Path | [4096]byte | NUL-padded (AF_UNIX path max is 108 bytes on Linux; the buffer is generously oversized) |
| **4128** | *(end)* | | total record size |

## 8. `FlowCloseRecord` (kind=8, net.flow_close via inet_sock_set_state) — 74 bytes

| Offset | Field | Type |
|---|---|---|
| 0 | Version | uint8 |
| 1 | Kind | uint8 |
| 2 | Proto | uint8 |
| 3 | Family | uint8 |
| 4 | Pid | uint32 |
| 8 | Cgid | uint64 |
| 16 | TsMono | uint64 |
| 24 | TsWall | uint64 |
| 32 | Daddr | [16]byte |
| 48 | Dport | uint16 |
| 50 | BytesTx | uint64 |
| 58 | BytesRx | uint64 |
| 66 | DurNs | uint64 |
| **74** | *(end)* | total record size |

## 9. `DNSRecord` (kind=9, net.dns via cgroup_skb/egress port-53 parse) — 356 bytes

Up to 4 answer addresses are carried per record (plan: "≤4 questions"; we
also cap answers at 4 — more answers set `AnswersTruncated=1` and are
dropped past the 4th).

| Offset | Field | Type | Notes |
|---|---|---|---|
| 0 | Version | uint8 | |
| 1 | Kind | uint8 | =9 |
| 2 | Pid | uint32 | |
| 6 | Cgid | uint64 | |
| 14 | TsMono | uint64 | |
| 22 | TsWall | uint64 | |
| 30 | TTL | uint32 | seconds |
| 34 | QnameLen | uint8 | valid bytes in Qname, ≤255 |
| 35 | Qname | [255]byte | NUL-padded; dotted-ASCII, already decoded from DNS wire format by the BPF side |
| 290 | AnswerCount | uint8 | valid entries in Answers, ≤4 |
| 291 | AnswersTruncated | uint8 | 1 iff there were more than 4 answers |
| 292 | Answers | [4][16]byte | v4-mapped for IPv4 answers; entries at index ≥ AnswerCount are zero and MUST be ignored |
| **356** | *(end)* | | total record size |

## 10. `MigrationRecord` (kind=10, cgroup_attach_task — escape/migration precursor) — 38 bytes

Carries the raw fact of a pid migrating cgroups; `Enricher` resolves
`FromCgid`/`ToCgid` to session ids (or reports "unknown" for a foreign,
unmapped cgroup) before building `schema.NewAlertCgroupEscape`.

| Offset | Field | Type |
|---|---|---|
| 0 | Version | uint8 |
| 1 | Kind | uint8 |
| 2 | Pid | uint32 |
| 6 | FromCgid | uint64 |
| 14 | ToCgid | uint64 |
| 22 | TsMono | uint64 |
| 30 | TsWall | uint64 |
| **38** | *(end)* | total record size |

---

## Decode safety (fuzz requirement)

Every `DecodeXxx` function in `records.go`:

1. Checks the buffer is at least the record's fixed size before reading any
   multi-byte field (`ErrShortBuffer` otherwise).
2. Checks `Version` equals the supported version (`ErrUnsupportedVersion`
   otherwise) and, for `DecodeRecord`, that `Kind` matches a known registry
   entry (`ErrUnknownKind` otherwise).
3. Checks every `*Len` field against its field's declared capacity before
   slicing (`ErrLenOutOfRange` otherwise) — a corrupted or adversarial
   `*Len` can never cause an out-of-bounds slice.
4. Never panics on any input, including the empty slice, a truncated
   buffer, or a buffer with an all-0xFF `*Len` field. `FuzzDecodeRecord` in
   `records_test.go` asserts this over arbitrary byte input.
