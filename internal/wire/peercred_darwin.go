//go:build darwin

package wire

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred implements PeerCred on darwin via LOCAL_PEERCRED (Xucred).
func peerCred(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("wire: SyscallConn: %w", err)
	}

	var xucred *unix.Xucred
	var sockErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		xucred, sockErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, fmt.Errorf("wire: raw.Control: %w", ctrlErr)
	}
	if sockErr != nil {
		return 0, fmt.Errorf("wire: getsockopt LOCAL_PEERCRED: %w", sockErr)
	}
	return xucred.Uid, nil
}
