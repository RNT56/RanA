//go:build !linux && !darwin

package wire

import "net"

// peerCred stubs PeerCred on platforms with no implemented peer-credential
// mechanism (v1 targets linux + darwin only, CLAUDE.md §2). It always
// returns ErrPeerCredUnsupported so callers fail loudly and portably rather
// than getting a bogus uid.
func peerCred(conn *net.UnixConn) (uint32, error) {
	return 0, ErrPeerCredUnsupported
}
