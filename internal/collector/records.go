// Package collector decodes RanA's fixed-layout eBPF ring-buffer records
// into Go values, enriches them into schema.Event (cgid -> session,
// redaction), joins DNS answers to subsequent connects, and governs event
// flow under load (CONTRACTS §internal/collector, plan D7/D14/§4.3,
// docs/ARCHITECTURE.md §2/§4).
//
// This package is fully portable: it has no linux build tags and no
// dependency on internal/bpf. All tests exercise it against synthetic wire
// bytes, matching the byte-by-byte layouts documented in
// internal/bpf/records.md (the canonical spec — records.go MUST match it
// exactly; TestRecordLayoutsMatchDoc in records_test.go cross-checks the
// Size* constants against that document).
package collector

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// Record-kind byte values (second byte of every wire record, after the
// version byte). See internal/bpf/records.md "Record kind registry".
const (
	RecordKindExec        uint8 = 1
	RecordKindFork        uint8 = 2
	RecordKindExit        uint8 = 3
	RecordKindFsOp        uint8 = 4
	RecordKindConnect     uint8 = 5
	RecordKindSendmsg     uint8 = 6
	RecordKindUnixConnect uint8 = 7
	RecordKindFlowClose   uint8 = 8
	RecordKindDNS         uint8 = 9
	RecordKindMigration   uint8 = 10
)

// recordVersion is the only wire version this decoder understands (v1).
const recordVersion uint8 = 1

// Fixed record sizes in bytes, exactly matching internal/bpf/records.md.
const (
	SizeExecRecord        = 8254
	SizeForkRecord        = 34
	SizeExitRecord        = 50
	SizeFsOpRecord        = 4148
	SizeConnectRecord     = 50
	SizeSendmsgRecord     = 50
	SizeUnixConnectRecord = 4128
	SizeFlowCloseRecord   = 74
	SizeDNSRecord         = 356
	SizeMigrationRecord   = 38
)

// Field capacities (max valid-byte lengths for length-prefixed fields),
// per internal/bpf/records.md.
const (
	capExecComm    = 16
	capExecExePath = 1024
	capExecCwd     = 1024
	capExecArgv    = 6144

	capFsOpPath  = 2048
	capFsOpPath2 = 2048

	capUnixConnectPath = 4096

	capDNSQname   = 255
	capDNSAnswers = 4
)

// Decode errors. Every DecodeXxx function returns one of these (never a
// panic) on malformed input — the fuzz tests in records_test.go assert
// this over arbitrary byte input.
var (
	// ErrShortBuffer is returned when the input is smaller than the
	// record's fixed wire size.
	ErrShortBuffer = errors.New("collector: buffer too short for record")
	// ErrUnsupportedVersion is returned when the record's Version byte is
	// not one this decoder understands.
	ErrUnsupportedVersion = errors.New("collector: unsupported record version")
	// ErrUnknownKind is returned by DecodeRecord when the Kind byte does
	// not match any entry in the record-kind registry.
	ErrUnknownKind = errors.New("collector: unknown record kind")
	// ErrLenOutOfRange is returned when a length-prefix field (*Len,
	// AnswerCount, ...) exceeds its field's declared capacity, or when a
	// PathSource/Op byte does not match a known enum value. Guards every
	// slice bound so a corrupted or adversarial length can never cause an
	// out-of-bounds read.
	ErrLenOutOfRange = errors.New("collector: length field out of range")
)

// PathSourceKind mirrors schema.PathSource for the wire record's 1-byte
// encoding (0=resolved, 1=claimed). See internal/bpf/records.md §4.
type PathSourceKind uint8

// PathSourceKind wire values.
const (
	PathSourceKindResolved PathSourceKind = 0
	PathSourceKindClaimed  PathSourceKind = 1
)

// FsOp identifies which fs.* kernel event a FsOpRecord carries.
type FsOp uint8

// FsOp wire values, per internal/bpf/records.md §4.
const (
	FsOpWriteOpen FsOp = 1
	FsOpUnlink    FsOp = 2
	FsOpRename    FsOp = 3
	FsOpMkdir     FsOp = 4
	FsOpChmod     FsOp = 5
	FsOpTruncate  FsOp = 6
)

func checkLen(buf []byte, size int) error {
	if len(buf) < size {
		return ErrShortBuffer
	}
	return nil
}

func checkVersion(buf []byte) error {
	if len(buf) < 1 {
		return ErrShortBuffer
	}
	if buf[0] != recordVersion {
		return ErrUnsupportedVersion
	}
	return nil
}

// decodeStr reads a length-prefixed, NUL-padded string field. n is the
// valid-byte count already read from the wire; capacity is the field's
// fixed buffer size. Returns ErrLenOutOfRange if n exceeds capacity.
func decodeStr(buf []byte, off, capacity int, n int) (string, error) {
	if n < 0 || n > capacity {
		return "", ErrLenOutOfRange
	}
	return string(buf[off : off+n]), nil
}

// ---- ExecRecord ----

// ExecRecord is the decoded form of a wire proc.exec record (kind=1).
type ExecRecord struct {
	Pid           uint32
	Ppid          uint32
	Uid           uint32
	Cgid          uint64
	TsMono        uint64
	TsWall        uint64
	Comm          string
	ExePath       string
	Cwd           string
	Argv          []string
	ArgvTruncated bool
}

// DecodeExecRecord decodes a wire ExecRecord per internal/bpf/records.md §1.
func DecodeExecRecord(buf []byte) (ExecRecord, error) {
	var rec ExecRecord
	if err := checkLen(buf, SizeExecRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}

	rec.Pid = binary.LittleEndian.Uint32(buf[2:6])
	rec.Ppid = binary.LittleEndian.Uint32(buf[6:10])
	rec.Uid = binary.LittleEndian.Uint32(buf[10:14])
	rec.Cgid = binary.LittleEndian.Uint64(buf[14:22])
	rec.TsMono = binary.LittleEndian.Uint64(buf[22:30])
	rec.TsWall = binary.LittleEndian.Uint64(buf[30:38])

	commLen := int(buf[38])
	comm, err := decodeStr(buf, 39, capExecComm, commLen)
	if err != nil {
		return ExecRecord{}, err
	}
	rec.Comm = comm

	exePathLen := int(binary.LittleEndian.Uint16(buf[55:57]))
	exePath, err := decodeStr(buf, 57, capExecExePath, exePathLen)
	if err != nil {
		return ExecRecord{}, err
	}
	rec.ExePath = exePath

	cwdLen := int(binary.LittleEndian.Uint16(buf[1081:1083]))
	cwd, err := decodeStr(buf, 1083, capExecCwd, cwdLen)
	if err != nil {
		return ExecRecord{}, err
	}
	rec.Cwd = cwd

	argvLen := int(binary.LittleEndian.Uint16(buf[2107:2109]))
	rec.ArgvTruncated = buf[2109] != 0
	argvRaw, err := decodeStr(buf, 2110, capExecArgv, argvLen)
	if err != nil {
		return ExecRecord{}, err
	}
	rec.Argv = splitArgv(argvRaw)

	return rec, nil
}

// splitArgv splits a NUL-separated argv blob into individual arguments,
// dropping a single trailing empty token produced by a trailing NUL (the
// common C argv-serialization shape).
func splitArgv(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := bytes.Split([]byte(raw), []byte{0})
	out := make([]string, 0, len(parts))
	for i, p := range parts {
		if i == len(parts)-1 && len(p) == 0 {
			continue // trailing NUL produced an empty final token
		}
		out = append(out, string(p))
	}
	return out
}

// ---- ForkRecord ----

// ForkRecord is the decoded form of a wire proc.fork record (kind=2).
type ForkRecord struct {
	Pid    uint32
	Ppid   uint32
	Cgid   uint64
	TsMono uint64
	TsWall uint64
}

// DecodeForkRecord decodes a wire ForkRecord per internal/bpf/records.md §2.
func DecodeForkRecord(buf []byte) (ForkRecord, error) {
	var rec ForkRecord
	if err := checkLen(buf, SizeForkRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}
	rec.Pid = binary.LittleEndian.Uint32(buf[2:6])
	rec.Ppid = binary.LittleEndian.Uint32(buf[6:10])
	rec.Cgid = binary.LittleEndian.Uint64(buf[10:18])
	rec.TsMono = binary.LittleEndian.Uint64(buf[18:26])
	rec.TsWall = binary.LittleEndian.Uint64(buf[26:34])
	return rec, nil
}

// ---- ExitRecord ----

// ExitRecord is the decoded form of a wire proc.exit record (kind=3).
type ExitRecord struct {
	Pid      uint32
	Cgid     uint64
	TsMono   uint64
	TsWall   uint64
	ExitCode int32
	UtimeNs  uint64
	StimeNs  uint64
}

// DecodeExitRecord decodes a wire ExitRecord per internal/bpf/records.md §3.
func DecodeExitRecord(buf []byte) (ExitRecord, error) {
	var rec ExitRecord
	if err := checkLen(buf, SizeExitRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}
	rec.Pid = binary.LittleEndian.Uint32(buf[2:6])
	rec.Cgid = binary.LittleEndian.Uint64(buf[6:14])
	rec.TsMono = binary.LittleEndian.Uint64(buf[14:22])
	rec.TsWall = binary.LittleEndian.Uint64(buf[22:30])
	rec.ExitCode = int32(binary.LittleEndian.Uint32(buf[30:34]))
	rec.UtimeNs = binary.LittleEndian.Uint64(buf[34:42])
	rec.StimeNs = binary.LittleEndian.Uint64(buf[42:50])
	return rec, nil
}

// ---- FsOpRecord ----

// FsOpRecord is the decoded form of a wire fs.* record (kind=4): write_open,
// unlink, rename, mkdir, chmod, or truncate, distinguished by Op.
type FsOpRecord struct {
	Op         FsOp
	PathSource PathSourceKind
	Pid        uint32
	Cgid       uint64
	TsMono     uint64
	TsWall     uint64
	Flags      uint64
	Mode       uint64
	Path       string
	Path2      string // rename destination only; empty otherwise
}

// DecodeFsOpRecord decodes a wire FsOpRecord per internal/bpf/records.md §4.
func DecodeFsOpRecord(buf []byte) (FsOpRecord, error) {
	var rec FsOpRecord
	if err := checkLen(buf, SizeFsOpRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}

	op := FsOp(buf[2])
	switch op {
	case FsOpWriteOpen, FsOpUnlink, FsOpRename, FsOpMkdir, FsOpChmod, FsOpTruncate:
	default:
		return FsOpRecord{}, ErrLenOutOfRange
	}
	rec.Op = op

	ps := PathSourceKind(buf[3])
	switch ps {
	case PathSourceKindResolved, PathSourceKindClaimed:
	default:
		return FsOpRecord{}, ErrLenOutOfRange
	}
	rec.PathSource = ps

	rec.Pid = binary.LittleEndian.Uint32(buf[4:8])
	rec.Cgid = binary.LittleEndian.Uint64(buf[8:16])
	rec.TsMono = binary.LittleEndian.Uint64(buf[16:24])
	rec.TsWall = binary.LittleEndian.Uint64(buf[24:32])
	rec.Flags = binary.LittleEndian.Uint64(buf[32:40])
	rec.Mode = binary.LittleEndian.Uint64(buf[40:48])

	pathLen := int(binary.LittleEndian.Uint16(buf[48:50]))
	path, err := decodeStr(buf, 50, capFsOpPath, pathLen)
	if err != nil {
		return FsOpRecord{}, err
	}
	rec.Path = path

	path2Len := int(binary.LittleEndian.Uint16(buf[2098:2100]))
	path2, err := decodeStr(buf, 2100, capFsOpPath2, path2Len)
	if err != nil {
		return FsOpRecord{}, err
	}
	rec.Path2 = path2

	return rec, nil
}

// ---- ConnectRecord / SendmsgRecord ----

// ConnectRecord is the decoded form of a wire net.connect record produced
// by cgroup/connect4·6 (kind=5).
type ConnectRecord struct {
	Proto  uint8 // 6=TCP, 17=UDP
	Family uint8 // 4 or 6
	Pid    uint32
	Cgid   uint64
	TsMono uint64
	TsWall uint64
	Daddr  [16]byte
	Dport  uint16
}

// SendmsgRecord is the decoded form of a wire net.connect record produced
// by cgroup/sendmsg4·6 for unconnected UDP (kind=6). Field-for-field
// identical to ConnectRecord; kept as a distinct Go type so callers cannot
// confuse the two record kinds by construction.
type SendmsgRecord ConnectRecord

func decodeConnectLike(buf []byte, size int) (ConnectRecord, error) {
	var rec ConnectRecord
	if err := checkLen(buf, size); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}
	rec.Proto = buf[2]
	rec.Family = buf[3]
	rec.Pid = binary.LittleEndian.Uint32(buf[4:8])
	rec.Cgid = binary.LittleEndian.Uint64(buf[8:16])
	rec.TsMono = binary.LittleEndian.Uint64(buf[16:24])
	rec.TsWall = binary.LittleEndian.Uint64(buf[24:32])
	copy(rec.Daddr[:], buf[32:48])
	rec.Dport = binary.LittleEndian.Uint16(buf[48:50])
	return rec, nil
}

// DecodeConnectRecord decodes a wire ConnectRecord per
// internal/bpf/records.md §5.
func DecodeConnectRecord(buf []byte) (ConnectRecord, error) {
	return decodeConnectLike(buf, SizeConnectRecord)
}

// DecodeSendmsgRecord decodes a wire SendmsgRecord per
// internal/bpf/records.md §6.
func DecodeSendmsgRecord(buf []byte) (SendmsgRecord, error) {
	rec, err := decodeConnectLike(buf, SizeSendmsgRecord)
	return SendmsgRecord(rec), err
}

// ---- UnixConnectRecord ----

// UnixConnectRecord is the decoded form of a wire unix.connect record
// (kind=7).
type UnixConnectRecord struct {
	Pid    uint32
	Cgid   uint64
	TsMono uint64
	TsWall uint64
	Path   string
}

// DecodeUnixConnectRecord decodes a wire UnixConnectRecord per
// internal/bpf/records.md §7.
func DecodeUnixConnectRecord(buf []byte) (UnixConnectRecord, error) {
	var rec UnixConnectRecord
	if err := checkLen(buf, SizeUnixConnectRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}
	rec.Pid = binary.LittleEndian.Uint32(buf[2:6])
	rec.Cgid = binary.LittleEndian.Uint64(buf[6:14])
	rec.TsMono = binary.LittleEndian.Uint64(buf[14:22])
	rec.TsWall = binary.LittleEndian.Uint64(buf[22:30])

	pathLen := int(binary.LittleEndian.Uint16(buf[30:32]))
	path, err := decodeStr(buf, 32, capUnixConnectPath, pathLen)
	if err != nil {
		return UnixConnectRecord{}, err
	}
	rec.Path = path
	return rec, nil
}

// ---- FlowCloseRecord ----

// FlowCloseRecord is the decoded form of a wire net.flow_close record
// (kind=8).
type FlowCloseRecord struct {
	Proto   uint8
	Family  uint8
	Pid     uint32
	Cgid    uint64
	TsMono  uint64
	TsWall  uint64
	Daddr   [16]byte
	Dport   uint16
	BytesTx uint64
	BytesRx uint64
	DurNs   uint64
}

// DecodeFlowCloseRecord decodes a wire FlowCloseRecord per
// internal/bpf/records.md §8.
func DecodeFlowCloseRecord(buf []byte) (FlowCloseRecord, error) {
	var rec FlowCloseRecord
	if err := checkLen(buf, SizeFlowCloseRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}
	rec.Proto = buf[2]
	rec.Family = buf[3]
	rec.Pid = binary.LittleEndian.Uint32(buf[4:8])
	rec.Cgid = binary.LittleEndian.Uint64(buf[8:16])
	rec.TsMono = binary.LittleEndian.Uint64(buf[16:24])
	rec.TsWall = binary.LittleEndian.Uint64(buf[24:32])
	copy(rec.Daddr[:], buf[32:48])
	rec.Dport = binary.LittleEndian.Uint16(buf[48:50])
	rec.BytesTx = binary.LittleEndian.Uint64(buf[50:58])
	rec.BytesRx = binary.LittleEndian.Uint64(buf[58:66])
	rec.DurNs = binary.LittleEndian.Uint64(buf[66:74])
	return rec, nil
}

// ---- DNSRecord ----

// DNSRecord is the decoded form of a wire net.dns record (kind=9).
type DNSRecord struct {
	Pid              uint32
	Cgid             uint64
	TsMono           uint64
	TsWall           uint64
	TTL              uint32
	Qname            string
	Answers          [][16]byte
	AnswersTruncated bool
}

// DecodeDNSRecord decodes a wire DNSRecord per internal/bpf/records.md §9.
func DecodeDNSRecord(buf []byte) (DNSRecord, error) {
	var rec DNSRecord
	if err := checkLen(buf, SizeDNSRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}
	rec.Pid = binary.LittleEndian.Uint32(buf[2:6])
	rec.Cgid = binary.LittleEndian.Uint64(buf[6:14])
	rec.TsMono = binary.LittleEndian.Uint64(buf[14:22])
	rec.TsWall = binary.LittleEndian.Uint64(buf[22:30])
	rec.TTL = binary.LittleEndian.Uint32(buf[30:34])

	qnameLen := int(buf[34])
	qname, err := decodeStr(buf, 35, capDNSQname, qnameLen)
	if err != nil {
		return DNSRecord{}, err
	}
	rec.Qname = qname

	answerCount := int(buf[290])
	if answerCount > capDNSAnswers {
		return DNSRecord{}, ErrLenOutOfRange
	}
	rec.AnswersTruncated = buf[291] != 0

	answers := make([][16]byte, 0, answerCount)
	for i := 0; i < answerCount; i++ {
		off := 292 + i*16
		var a [16]byte
		copy(a[:], buf[off:off+16])
		answers = append(answers, a)
	}
	rec.Answers = answers

	return rec, nil
}

// ---- MigrationRecord ----

// MigrationRecord is the decoded form of a wire cgroup-migration record
// (kind=10), the raw precursor fact behind alert.cgroup_escape.
type MigrationRecord struct {
	Pid      uint32
	FromCgid uint64
	ToCgid   uint64
	TsMono   uint64
	TsWall   uint64
}

// DecodeMigrationRecord decodes a wire MigrationRecord per
// internal/bpf/records.md §10.
func DecodeMigrationRecord(buf []byte) (MigrationRecord, error) {
	var rec MigrationRecord
	if err := checkLen(buf, SizeMigrationRecord); err != nil {
		return rec, err
	}
	if err := checkVersion(buf); err != nil {
		return rec, err
	}
	rec.Pid = binary.LittleEndian.Uint32(buf[2:6])
	rec.FromCgid = binary.LittleEndian.Uint64(buf[6:14])
	rec.ToCgid = binary.LittleEndian.Uint64(buf[14:22])
	rec.TsMono = binary.LittleEndian.Uint64(buf[22:30])
	rec.TsWall = binary.LittleEndian.Uint64(buf[30:38])
	return rec, nil
}

// ---- top-level dispatch ----

// DecodeRecord inspects the Version and Kind header bytes and dispatches to
// the matching DecodeXxx function, returning the decoded record as one of
// the Xxx types defined in this file. Never panics on any input, including
// nil or truncated buffers (FuzzDecodeRecord).
func DecodeRecord(buf []byte) (any, error) {
	if len(buf) < 2 {
		return nil, ErrShortBuffer
	}
	if buf[0] != recordVersion {
		return nil, ErrUnsupportedVersion
	}
	switch buf[1] {
	case RecordKindExec:
		return DecodeExecRecord(buf)
	case RecordKindFork:
		return DecodeForkRecord(buf)
	case RecordKindExit:
		return DecodeExitRecord(buf)
	case RecordKindFsOp:
		return DecodeFsOpRecord(buf)
	case RecordKindConnect:
		return DecodeConnectRecord(buf)
	case RecordKindSendmsg:
		return DecodeSendmsgRecord(buf)
	case RecordKindUnixConnect:
		return DecodeUnixConnectRecord(buf)
	case RecordKindFlowClose:
		return DecodeFlowCloseRecord(buf)
	case RecordKindDNS:
		return DecodeDNSRecord(buf)
	case RecordKindMigration:
		return DecodeMigrationRecord(buf)
	default:
		return nil, ErrUnknownKind
	}
}
