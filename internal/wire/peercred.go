package wire

import (
	"errors"
	"net"
)

// ErrNilConn is returned by PeerCred when passed a nil *net.UnixConn.
var ErrNilConn = errors.New("wire: nil unix connection")

// ErrPeerCredUnsupported is returned by PeerCred on platforms with no
// implemented peer-credential mechanism.
var ErrPeerCredUnsupported = errors.New("wire: peer credentials not supported on this platform")

// PeerCred returns the effective UID of the process on the other end of a
// unix domain socket connection: SO_PEERCRED on linux, LOCAL_PEERCRED
// (Xucred) on darwin. This is used once, at connection setup, to gate the
// ranad<->svc socket to the owning uid (docs/THREAT-MODEL.md §4) — it is not
// a per-frame check and does not touch the frame codec above.
//
// The concrete implementation lives in the platform-specific
// peercred_linux.go / peercred_darwin.go (and a stub peercred_other.go for
// any other GOOS, which always returns ErrPeerCredUnsupported).
func PeerCred(conn *net.UnixConn) (uid uint32, err error) {
	if conn == nil {
		return 0, ErrNilConn
	}
	return peerCred(conn)
}
