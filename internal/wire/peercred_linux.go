//go:build linux

package wire

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred implements PeerCred on linux via SO_PEERCRED.
func peerCred(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("wire: SyscallConn: %w", err)
	}

	var ucred *unix.Ucred
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("wire: raw.Control: %w", ctrlErr)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("wire: getsockopt SO_PEERCRED: %w", sockErr)
	}
	return ucred.Uid, nil
}
