package wire

import (
	"bytes"
	"testing"
)

// FuzzReadFrame feeds arbitrary byte streams into ReadFrame and asserts only
// that it never panics — garbage, torn, and oversize inputs must all come
// back as an error, never a crash (CONTRACTS §internal/wire).
func FuzzReadFrame(f *testing.F) {
	seeds := [][]byte{
		{},
		{0x00},
		{0x80},
		{0xFF, 0xFF, 0xFF, 0xFF, 0x0F},
		{0x01, 0xA1},
		{0x05, 0xA1, 0x61, 'x', 0x01, 0x02, 0x03},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	// Also seed with real, well-formed frames so the fuzzer starts from
	// valid structure and mutates outward.
	var buf bytes.Buffer
	_ = WriteFrame(&buf, &Hello{V: 1, Role: RoleSVC, Salt: []byte{1, 2, 3, 4}})
	f.Add(append([]byte(nil), buf.Bytes()...))

	buf.Reset()
	_ = WriteFrame(&buf, &Ev{Event: []byte{0xA0}})
	f.Add(append([]byte(nil), buf.Bytes()...))

	buf.Reset()
	_ = WriteFrame(&buf, &Head{Report: HeadReport{SessionID: "s", SegLast: 1, At: 2}})
	f.Add(append([]byte(nil), buf.Bytes()...))

	buf.Reset()
	_ = WriteFrame(&buf, &Bye{})
	f.Add(append([]byte(nil), buf.Bytes()...))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadFrame panicked on input %x: %v", data, r)
			}
		}()
		r := bytes.NewReader(data)
		// Drain up to a handful of frames in case the fuzzer produced a
		// multi-frame stream; a single call is also fine since ReadFrame
		// only ever consumes one frame's worth.
		for i := 0; i < 8; i++ {
			_, err := ReadFrame(r)
			if err != nil {
				return
			}
		}
	})
}
