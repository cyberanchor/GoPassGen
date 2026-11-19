//go:build unix

package cli

import (
	"io/fs"
	"os"
	"syscall"
)

// copyOwner gives a replacement file the owner and group of the original where
// the operating system permits it. Each is tried separately, because an
// unprivileged user may be able to set the group but never the owner.
func copyOwner(f *os.File, original fs.FileInfo) {
	if st, ok := original.Sys().(*syscall.Stat_t); ok {
		_ = f.Chown(int(st.Uid), -1)
		_ = f.Chown(-1, int(st.Gid))
	}
}
