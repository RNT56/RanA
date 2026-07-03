package collector

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// ---- layout cross-check against internal/bpf/records.md ----
//
// These sizes/offsets are transcribed from the "Ground truth" tables in
// internal/bpf/records.md. If you change records.go's layout, update the
// doc first (it's the canonical spec) and then this test.

func TestRecordLayoutsMatchDoc(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"SizeExecRecord", SizeExecRecord, 8254},
		{"SizeForkRecord", SizeForkRecord, 34},
		{"SizeExitRecord", SizeExitRecord, 50},
		{"SizeFsOpRecord", SizeFsOpRecord, 4148},
		{"SizeConnectRecord", SizeConnectRecord, 50},
		{"SizeSendmsgRecord", SizeSendmsgRecord, 50},
		{"SizeUnixConnectRecord", SizeUnixConnectRecord, 4128},
		{"SizeFlowCloseRecord", SizeFlowCloseRecord, 74},
		{"SizeDNSRecord", SizeDNSRecord, 356},
		{"SizeMigrationRecord", SizeMigrationRecord, 38},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("%s = %d, want %d (per internal/bpf/records.md)", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestRecordKindConstants(t *testing.T) {
	tests := []struct {
		name string
		got  uint8
		want uint8
	}{
		{"RecordKindExec", RecordKindExec, 1},
		{"RecordKindFork", RecordKindFork, 2},
		{"RecordKindExit", RecordKindExit, 3},
		{"RecordKindFsOp", RecordKindFsOp, 4},
		{"RecordKindConnect", RecordKindConnect, 5},
		{"RecordKindSendmsg", RecordKindSendmsg, 6},
		{"RecordKindUnixConnect", RecordKindUnixConnect, 7},
		{"RecordKindFlowClose", RecordKindFlowClose, 8},
		{"RecordKindDNS", RecordKindDNS, 9},
		{"RecordKindMigration", RecordKindMigration, 10},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s = %d, want %d", tt.name, tt.got, tt.want)
		}
	}
}

// ---- helpers to build synthetic wire bytes for each record kind ----

func putStr(buf []byte, off int, capacity int, s string) {
	copy(buf[off:off+capacity], s)
}

func execRecordBytes(t *testing.T, pid, ppid, uid uint32, cgid, tsMono, tsWall uint64, comm, exePath, cwd string, argv []string) []byte {
	t.Helper()
	buf := make([]byte, SizeExecRecord)
	buf[0] = 1
	buf[1] = RecordKindExec
	binary.LittleEndian.PutUint32(buf[2:6], pid)
	binary.LittleEndian.PutUint32(buf[6:10], ppid)
	binary.LittleEndian.PutUint32(buf[10:14], uid)
	binary.LittleEndian.PutUint64(buf[14:22], cgid)
	binary.LittleEndian.PutUint64(buf[22:30], tsMono)
	binary.LittleEndian.PutUint64(buf[30:38], tsWall)
	buf[38] = byte(len(comm))
	putStr(buf, 39, 16, comm)
	binary.LittleEndian.PutUint16(buf[55:57], uint16(len(exePath)))
	putStr(buf, 57, 1024, exePath)
	binary.LittleEndian.PutUint16(buf[1081:1083], uint16(len(cwd)))
	putStr(buf, 1083, 1024, cwd)

	argvJoined := joinNUL(argv)
	binary.LittleEndian.PutUint16(buf[2107:2109], uint16(len(argvJoined)))
	buf[2109] = 0
	putStr(buf, 2110, 6144, argvJoined)
	return buf
}

func joinNUL(parts []string) string {
	var b bytes.Buffer
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(0)
		}
		b.WriteString(p)
	}
	return b.String()
}

// ---- ExecRecord ----

func TestDecodeExecRecord(t *testing.T) {
	argv := []string{"/usr/bin/node", "--version"}
	buf := execRecordBytes(t, 100, 1, 501, 0xCAFE, 111, 222, "node", "/usr/bin/node", "/home/user", argv)

	rec, err := DecodeExecRecord(buf)
	if err != nil {
		t.Fatalf("DecodeExecRecord: %v", err)
	}
	if rec.Pid != 100 || rec.Ppid != 1 || rec.Uid != 501 || rec.Cgid != 0xCAFE {
		t.Errorf("ids mismatch: %+v", rec)
	}
	if rec.TsMono != 111 || rec.TsWall != 222 {
		t.Errorf("timestamps mismatch: %+v", rec)
	}
	if rec.Comm != "node" {
		t.Errorf("Comm = %q, want node", rec.Comm)
	}
	if rec.ExePath != "/usr/bin/node" {
		t.Errorf("ExePath = %q", rec.ExePath)
	}
	if rec.Cwd != "/home/user" {
		t.Errorf("Cwd = %q", rec.Cwd)
	}
	if len(rec.Argv) != 2 || rec.Argv[0] != "/usr/bin/node" || rec.Argv[1] != "--version" {
		t.Errorf("Argv = %#v", rec.Argv)
	}
	if rec.ArgvTruncated {
		t.Errorf("ArgvTruncated = true, want false")
	}
}

func TestDecodeExecRecordArgvTruncatedFlag(t *testing.T) {
	buf := execRecordBytes(t, 1, 1, 0, 1, 1, 1, "x", "/x", "/", []string{"a", "b"})
	buf[2109] = 1 // simulate BPF-side truncation flag
	rec, err := DecodeExecRecord(buf)
	if err != nil {
		t.Fatalf("DecodeExecRecord: %v", err)
	}
	if !rec.ArgvTruncated {
		t.Errorf("ArgvTruncated = false, want true")
	}
}

func TestDecodeExecRecordEmptyArgv(t *testing.T) {
	buf := execRecordBytes(t, 1, 1, 0, 1, 1, 1, "x", "/x", "/", nil)
	rec, err := DecodeExecRecord(buf)
	if err != nil {
		t.Fatalf("DecodeExecRecord: %v", err)
	}
	if len(rec.Argv) != 0 {
		t.Errorf("Argv = %#v, want empty", rec.Argv)
	}
}

func TestDecodeExecRecordTrailingNULDropped(t *testing.T) {
	buf := make([]byte, SizeExecRecord)
	buf[0] = 1
	buf[1] = RecordKindExec
	argvRaw := "a\x00b\x00" // trailing NUL, as a C-style arg vector would produce
	binary.LittleEndian.PutUint16(buf[2107:2109], uint16(len(argvRaw)))
	putStr(buf, 2110, 6144, argvRaw)

	rec, err := DecodeExecRecord(buf)
	if err != nil {
		t.Fatalf("DecodeExecRecord: %v", err)
	}
	if len(rec.Argv) != 2 || rec.Argv[0] != "a" || rec.Argv[1] != "b" {
		t.Errorf("Argv = %#v, want [a b]", rec.Argv)
	}
}

func TestDecodeExecRecordShortBuffer(t *testing.T) {
	_, err := DecodeExecRecord(make([]byte, SizeExecRecord-1))
	if err != ErrShortBuffer {
		t.Errorf("err = %v, want ErrShortBuffer", err)
	}
}

func TestDecodeExecRecordUnsupportedVersion(t *testing.T) {
	buf := make([]byte, SizeExecRecord)
	buf[0] = 99
	_, err := DecodeExecRecord(buf)
	if err != ErrUnsupportedVersion {
		t.Errorf("err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeExecRecordLenOutOfRange(t *testing.T) {
	buf := make([]byte, SizeExecRecord)
	buf[0] = 1
	buf[1] = RecordKindExec
	binary.LittleEndian.PutUint16(buf[2107:2109], 0xFFFF) // ArgvLen way beyond capacity 6144
	_, err := DecodeExecRecord(buf)
	if err != ErrLenOutOfRange {
		t.Errorf("err = %v, want ErrLenOutOfRange", err)
	}
}

// ---- ForkRecord ----

func TestDecodeForkRecord(t *testing.T) {
	buf := make([]byte, SizeForkRecord)
	buf[0] = 1
	buf[1] = RecordKindFork
	binary.LittleEndian.PutUint32(buf[2:6], 42)
	binary.LittleEndian.PutUint32(buf[6:10], 7)
	binary.LittleEndian.PutUint64(buf[10:18], 0xABCD)
	binary.LittleEndian.PutUint64(buf[18:26], 500)
	binary.LittleEndian.PutUint64(buf[26:34], 600)

	rec, err := DecodeForkRecord(buf)
	if err != nil {
		t.Fatalf("DecodeForkRecord: %v", err)
	}
	if rec.Pid != 42 || rec.Ppid != 7 || rec.Cgid != 0xABCD || rec.TsMono != 500 || rec.TsWall != 600 {
		t.Errorf("rec = %+v", rec)
	}
}

func TestDecodeForkRecordShortBuffer(t *testing.T) {
	_, err := DecodeForkRecord(make([]byte, 3))
	if err != ErrShortBuffer {
		t.Errorf("err = %v, want ErrShortBuffer", err)
	}
}

// ---- ExitRecord ----

func TestDecodeExitRecord(t *testing.T) {
	buf := make([]byte, SizeExitRecord)
	buf[0] = 1
	buf[1] = RecordKindExit
	binary.LittleEndian.PutUint32(buf[2:6], 42)
	binary.LittleEndian.PutUint64(buf[6:14], 9)
	binary.LittleEndian.PutUint64(buf[14:22], 100)
	binary.LittleEndian.PutUint64(buf[22:30], 200)
	var negOne int32 = -1
	binary.LittleEndian.PutUint32(buf[30:34], uint32(negOne))
	binary.LittleEndian.PutUint64(buf[34:42], 1000)
	binary.LittleEndian.PutUint64(buf[42:50], 2000)

	rec, err := DecodeExitRecord(buf)
	if err != nil {
		t.Fatalf("DecodeExitRecord: %v", err)
	}
	if rec.Pid != 42 || rec.Cgid != 9 || rec.ExitCode != -1 || rec.UtimeNs != 1000 || rec.StimeNs != 2000 {
		t.Errorf("rec = %+v", rec)
	}
}

// ---- FsOpRecord ----

func TestDecodeFsOpRecord(t *testing.T) {
	buf := make([]byte, SizeFsOpRecord)
	buf[0] = 1
	buf[1] = RecordKindFsOp
	buf[2] = byte(FsOpWriteOpen)
	buf[3] = 0 // resolved
	binary.LittleEndian.PutUint32(buf[4:8], 55)
	binary.LittleEndian.PutUint64(buf[8:16], 77)
	binary.LittleEndian.PutUint64(buf[16:24], 10)
	binary.LittleEndian.PutUint64(buf[24:32], 20)
	binary.LittleEndian.PutUint64(buf[32:40], 0x241) // O_WRONLY|O_CREAT|O_TRUNC-ish
	binary.LittleEndian.PutUint64(buf[40:48], 0o644)
	path := "/home/user/out.txt"
	binary.LittleEndian.PutUint16(buf[48:50], uint16(len(path)))
	putStr(buf, 50, 2048, path)

	rec, err := DecodeFsOpRecord(buf)
	if err != nil {
		t.Fatalf("DecodeFsOpRecord: %v", err)
	}
	if rec.Op != FsOpWriteOpen || rec.PathSource != PathSourceKindResolved {
		t.Errorf("Op/PathSource = %v/%v", rec.Op, rec.PathSource)
	}
	if rec.Path != path {
		t.Errorf("Path = %q, want %q", rec.Path, path)
	}
	if rec.Path2 != "" {
		t.Errorf("Path2 = %q, want empty", rec.Path2)
	}
	if rec.Mode != 0o644 {
		t.Errorf("Mode = %o", rec.Mode)
	}
}

func TestDecodeFsOpRecordRenameHasPath2(t *testing.T) {
	buf := make([]byte, SizeFsOpRecord)
	buf[0] = 1
	buf[1] = RecordKindFsOp
	buf[2] = byte(FsOpRename)
	buf[3] = 1 // claimed
	src := "/a/old"
	dst := "/a/new"
	binary.LittleEndian.PutUint16(buf[48:50], uint16(len(src)))
	putStr(buf, 50, 2048, src)
	binary.LittleEndian.PutUint16(buf[2098:2100], uint16(len(dst)))
	putStr(buf, 2100, 2048, dst)

	rec, err := DecodeFsOpRecord(buf)
	if err != nil {
		t.Fatalf("DecodeFsOpRecord: %v", err)
	}
	if rec.Path != src || rec.Path2 != dst {
		t.Errorf("Path/Path2 = %q/%q", rec.Path, rec.Path2)
	}
	if rec.PathSource != PathSourceKindClaimed {
		t.Errorf("PathSource = %v, want claimed", rec.PathSource)
	}
}

func TestDecodeFsOpRecordUnknownPathSource(t *testing.T) {
	buf := make([]byte, SizeFsOpRecord)
	buf[0] = 1
	buf[1] = RecordKindFsOp
	buf[3] = 7 // invalid path source
	_, err := DecodeFsOpRecord(buf)
	if err == nil {
		t.Fatal("expected error for invalid path source byte")
	}
}

// ---- ConnectRecord / SendmsgRecord ----

func v4Mapped(a, b, c, d byte) [16]byte {
	var addr [16]byte
	addr[10] = 0xff
	addr[11] = 0xff
	addr[12], addr[13], addr[14], addr[15] = a, b, c, d
	return addr
}

func connectRecordBytes(kind uint8, proto, family uint8, pid uint32, cgid, tsMono, tsWall uint64, daddr [16]byte, dport uint16) []byte {
	buf := make([]byte, SizeConnectRecord)
	buf[0] = 1
	buf[1] = kind
	buf[2] = proto
	buf[3] = family
	binary.LittleEndian.PutUint32(buf[4:8], pid)
	binary.LittleEndian.PutUint64(buf[8:16], cgid)
	binary.LittleEndian.PutUint64(buf[16:24], tsMono)
	binary.LittleEndian.PutUint64(buf[24:32], tsWall)
	copy(buf[32:48], daddr[:])
	binary.LittleEndian.PutUint16(buf[48:50], dport)
	return buf
}

func TestDecodeConnectRecord(t *testing.T) {
	daddr := v4Mapped(93, 184, 216, 34)
	buf := connectRecordBytes(RecordKindConnect, 6, 4, 100, 1, 10, 20, daddr, 443)

	rec, err := DecodeConnectRecord(buf)
	if err != nil {
		t.Fatalf("DecodeConnectRecord: %v", err)
	}
	if rec.Proto != 6 || rec.Family != 4 || rec.Dport != 443 {
		t.Errorf("rec = %+v", rec)
	}
	if rec.Daddr != daddr {
		t.Errorf("Daddr = %v, want %v", rec.Daddr, daddr)
	}
}

func TestDecodeSendmsgRecord(t *testing.T) {
	daddr := v4Mapped(8, 8, 8, 8)
	buf := connectRecordBytes(RecordKindSendmsg, 17, 4, 100, 1, 10, 20, daddr, 53)
	rec, err := DecodeSendmsgRecord(buf)
	if err != nil {
		t.Fatalf("DecodeSendmsgRecord: %v", err)
	}
	if rec.Proto != 17 || rec.Dport != 53 {
		t.Errorf("rec = %+v", rec)
	}
}

// ---- UnixConnectRecord ----

func TestDecodeUnixConnectRecord(t *testing.T) {
	buf := make([]byte, SizeUnixConnectRecord)
	buf[0] = 1
	buf[1] = RecordKindUnixConnect
	binary.LittleEndian.PutUint32(buf[2:6], 9)
	binary.LittleEndian.PutUint64(buf[6:14], 3)
	binary.LittleEndian.PutUint64(buf[14:22], 1)
	binary.LittleEndian.PutUint64(buf[22:30], 2)
	path := "/var/run/docker.sock"
	binary.LittleEndian.PutUint16(buf[30:32], uint16(len(path)))
	putStr(buf, 32, 4096, path)

	rec, err := DecodeUnixConnectRecord(buf)
	if err != nil {
		t.Fatalf("DecodeUnixConnectRecord: %v", err)
	}
	if rec.Path != path {
		t.Errorf("Path = %q, want %q", rec.Path, path)
	}
}

// ---- FlowCloseRecord ----

func TestDecodeFlowCloseRecord(t *testing.T) {
	buf := make([]byte, SizeFlowCloseRecord)
	buf[0] = 1
	buf[1] = RecordKindFlowClose
	buf[2] = 6
	buf[3] = 4
	binary.LittleEndian.PutUint32(buf[4:8], 1)
	binary.LittleEndian.PutUint64(buf[8:16], 2)
	binary.LittleEndian.PutUint64(buf[16:24], 3)
	binary.LittleEndian.PutUint64(buf[24:32], 4)
	daddr := v4Mapped(1, 2, 3, 4)
	copy(buf[32:48], daddr[:])
	binary.LittleEndian.PutUint16(buf[48:50], 443)
	binary.LittleEndian.PutUint64(buf[50:58], 1024)
	binary.LittleEndian.PutUint64(buf[58:66], 2048)
	binary.LittleEndian.PutUint64(buf[66:74], 999)

	rec, err := DecodeFlowCloseRecord(buf)
	if err != nil {
		t.Fatalf("DecodeFlowCloseRecord: %v", err)
	}
	if rec.BytesTx != 1024 || rec.BytesRx != 2048 || rec.DurNs != 999 {
		t.Errorf("rec = %+v", rec)
	}
	if rec.Daddr != daddr || rec.Dport != 443 {
		t.Errorf("addr/port = %v/%d", rec.Daddr, rec.Dport)
	}
}

// ---- DNSRecord ----

func TestDecodeDNSRecord(t *testing.T) {
	buf := make([]byte, SizeDNSRecord)
	buf[0] = 1
	buf[1] = RecordKindDNS
	binary.LittleEndian.PutUint32(buf[2:6], 1)
	binary.LittleEndian.PutUint64(buf[6:14], 2)
	binary.LittleEndian.PutUint64(buf[14:22], 3)
	binary.LittleEndian.PutUint64(buf[22:30], 4)
	binary.LittleEndian.PutUint32(buf[30:34], 300)
	qname := "example.com"
	buf[34] = byte(len(qname))
	putStr(buf, 35, 255, qname)
	buf[290] = 2 // AnswerCount
	buf[291] = 0 // not truncated
	a1 := v4Mapped(93, 184, 216, 34)
	a2 := v4Mapped(93, 184, 216, 35)
	copy(buf[292:308], a1[:])
	copy(buf[308:324], a2[:])

	rec, err := DecodeDNSRecord(buf)
	if err != nil {
		t.Fatalf("DecodeDNSRecord: %v", err)
	}
	if rec.Qname != qname {
		t.Errorf("Qname = %q, want %q", rec.Qname, qname)
	}
	if rec.TTL != 300 {
		t.Errorf("TTL = %d", rec.TTL)
	}
	if len(rec.Answers) != 2 || rec.Answers[0] != a1 || rec.Answers[1] != a2 {
		t.Errorf("Answers = %v", rec.Answers)
	}
	if rec.AnswersTruncated {
		t.Errorf("AnswersTruncated = true, want false")
	}
}

func TestDecodeDNSRecordAnswerCountOutOfRange(t *testing.T) {
	buf := make([]byte, SizeDNSRecord)
	buf[0] = 1
	buf[1] = RecordKindDNS
	buf[290] = 250 // way over the 4-entry cap
	_, err := DecodeDNSRecord(buf)
	if err != ErrLenOutOfRange {
		t.Errorf("err = %v, want ErrLenOutOfRange", err)
	}
}

// ---- MigrationRecord ----

func TestDecodeMigrationRecord(t *testing.T) {
	buf := make([]byte, SizeMigrationRecord)
	buf[0] = 1
	buf[1] = RecordKindMigration
	binary.LittleEndian.PutUint32(buf[2:6], 12)
	binary.LittleEndian.PutUint64(buf[6:14], 100)
	binary.LittleEndian.PutUint64(buf[14:22], 200)
	binary.LittleEndian.PutUint64(buf[22:30], 5)
	binary.LittleEndian.PutUint64(buf[30:38], 6)

	rec, err := DecodeMigrationRecord(buf)
	if err != nil {
		t.Fatalf("DecodeMigrationRecord: %v", err)
	}
	if rec.Pid != 12 || rec.FromCgid != 100 || rec.ToCgid != 200 {
		t.Errorf("rec = %+v", rec)
	}
}

// ---- top-level dispatch ----

func TestDecodeRecordDispatch(t *testing.T) {
	buf := make([]byte, SizeForkRecord)
	buf[0] = 1
	buf[1] = RecordKindFork
	binary.LittleEndian.PutUint32(buf[2:6], 1)

	rec, err := DecodeRecord(buf)
	if err != nil {
		t.Fatalf("DecodeRecord: %v", err)
	}
	fr, ok := rec.(ForkRecord)
	if !ok {
		t.Fatalf("DecodeRecord returned %T, want ForkRecord", rec)
	}
	if fr.Pid != 1 {
		t.Errorf("Pid = %d", fr.Pid)
	}
}

func TestDecodeRecordUnknownKind(t *testing.T) {
	buf := []byte{1, 250, 0, 0}
	_, err := DecodeRecord(buf)
	if err != ErrUnknownKind {
		t.Errorf("err = %v, want ErrUnknownKind", err)
	}
}

func TestDecodeRecordEmptyBuffer(t *testing.T) {
	_, err := DecodeRecord(nil)
	if err != ErrShortBuffer {
		t.Errorf("err = %v, want ErrShortBuffer", err)
	}
}

// ---- fuzz: garbage never panics ----

func FuzzDecodeRecord(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Add([]byte{1, RecordKindExec})
	f.Add(make([]byte, SizeExecRecord))
	f.Add(make([]byte, SizeDNSRecord))
	seedFsOp := make([]byte, SizeFsOpRecord)
	seedFsOp[0], seedFsOp[1] = 1, RecordKindFsOp
	f.Add(seedFsOp)

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeRecord panicked on input len=%d: %v", len(data), r)
			}
		}()
		_, _ = DecodeRecord(data)
	})
}

func FuzzDecodeExecRecord(f *testing.F) {
	f.Add(make([]byte, SizeExecRecord))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeExecRecord panicked: %v", r)
			}
		}()
		_, _ = DecodeExecRecord(data)
	})
}

func FuzzDecodeFsOpRecord(f *testing.F) {
	f.Add(make([]byte, SizeFsOpRecord))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeFsOpRecord panicked: %v", r)
			}
		}()
		_, _ = DecodeFsOpRecord(data)
	})
}

func FuzzDecodeDNSRecord(f *testing.F) {
	f.Add(make([]byte, SizeDNSRecord))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("DecodeDNSRecord panicked: %v", r)
			}
		}()
		_, _ = DecodeDNSRecord(data)
	})
}
