//go:build !windows
// +build !windows

package utils

import (
	"fmt"
	"os"
	"strconv"
	_ "unsafe" // for go:linkname

	"golang.org/x/sys/unix"
)

// EnsureProcHandle returns whether or not the given file handle is on procfs.
func EnsureProcHandle(fh *os.File) error {
	var buf unix.Statfs_t
	if err := unix.Fstatfs(int(fh.Fd()), &buf); err != nil {
		return fmt.Errorf("ensure %s is on procfs: %w", fh.Name(), err)
	}
	if buf.Type != unix.PROC_SUPER_MAGIC {
		return fmt.Errorf("%s is not on procfs", fh.Name())
	}
	return nil
}

type fdFunc func(fd int)

// fdRangeFrom calls the passed fdFunc for each file descriptor that is open in
// the current process.
func fdRangeFrom(minFd int, fn fdFunc) error {
	// lr-x------ 1 root root 64 7月   3 18:07 0 -> /dev/null
	//lr-x------ 1 root root 64 7月   3 18:07 1 -> /dev/null
	//lrwx------ 1 root root 64 7月   3 18:07 10 -> 'socket:[114846]'
	//lr-x------ 1 root root 64 7月   3 18:07 11 -> 'pipe:[114847]'
	//l-wx------ 1 root root 64 7月   3 18:07 12 -> 'pipe:[114847]'
	//l--------- 1 root root 64 7月   3 18:07 13 -> /run/containerd/runc/k8s.io/130d1282fd8102efa1915c9d9409ea3e75571981eafac4785b0d7d59abd5f091/exec.fifo
	//lr-x------ 1 root root 64 7月   3 18:07 14 -> /proc/11126/fd
	//lr-x------ 1 root root 64 7月   3 18:07 2 -> /dev/null
	//lrwx------ 1 root root 64 7月   3 18:07 3 -> 'socket:[113863]'
	//l-wx------ 1 root root 64 7月   3 18:07 4 -> /run/containerd/io.containerd.runtime.v2.task/k8s.io/130d1282fd8102efa1915c9d9409ea3e75571981eafac4785b0d7d59abd5f091/log.json
	//lrwx------ 1 root root 64 7月   3 18:07 5 -> 'anon_inode:[eventpoll]'
	//lr-x------ 1 root root 64 7月   3 18:07 6 -> 'pipe:[113882]'
	//l-wx------ 1 root root 64 7月   3 18:07 7 -> 'pipe:[113882]'
	//l--------- 1 root root 64 7月   3 18:07 8 -> /sys/fs/cgroup
	//lrwx------ 1 root root 64 7月   3 18:07 9 -> 'socket:[114845]'

	//   cd /proc/$(pidof runc)/fd
	fdDir, err := os.Open("/proc/self/fd")
	if err != nil {
		return err
	}
	defer fdDir.Close()

	if err := EnsureProcHandle(fdDir); err != nil {
		return err
	}

	fdList, err := fdDir.Readdirnames(-1)
	if err != nil {
		return err
	}
	for _, fdStr := range fdList {
		fd, err := strconv.Atoi(fdStr)
		// Ignore non-numeric file names.
		if err != nil {
			continue
		}
		// Ignore descriptors lower than our specified minimum.
		if fd < minFd {
			continue
		}
		// Ignore the file descriptor we used for readdir, as it will be closed
		// when we return.
		if uintptr(fd) == fdDir.Fd() {
			continue
		}
		// Run the closure.
		fn(fd)
	}
	return nil
}

//go:linkname runtime_IsPollDescriptor internal/poll.IsPollDescriptor

// In order to make sure we do not close the internal epoll descriptors the Go
// runtime uses, we need to ensure that we skip descriptors that match
// "internal/poll".IsPollDescriptor. Yes, this is a Go runtime internal thing,
// unfortunately there's no other way to be sure we're only keeping the file
// descriptors the Go runtime needs. Hopefully nothing blows up doing this...
func runtime_IsPollDescriptor(fd uintptr) bool //nolint:revive

// UnsafeCloseFrom closes all file descriptors greater or equal to minFd in the
// current process, except for those critical to Go's runtime (such as the
// netpoll management descriptors).
//
// NOTE: That this function is incredibly dangerous to use in most Go code, as
// closing file descriptors from underneath *os.File handles can lead to very
// bad behaviour (the closed file descriptor can be re-used and then any
// *os.File operations would apply to the wrong file). This function is only
// intended to be called from the last stage of runc init.
func UnsafeCloseFrom(minFd int) error {
	// We must not close some file descriptors.
	return fdRangeFrom(minFd, func(fd int) {
		if runtime_IsPollDescriptor(uintptr(fd)) {
			// These are the Go runtimes internal netpoll file descriptors.
			// These file descriptors are operated on deep in the Go scheduler,
			// and closing those files from underneath Go can result in panics.
			// There is no issue with keeping them because they are not
			// executable and are not useful to an attacker anyway. Also we
			// don't have any choice.
			return
		}
		// There's nothing we can do about errors from close(2), and the
		// only likely error to be seen is EBADF which indicates the fd was
		// already closed (in which case, we got what we wanted).
		_ = unix.Close(fd)
	})
}

// NewSockPair returns a new unix socket pair
func NewSockPair(name string) (parent *os.File, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), name+"-p"), os.NewFile(uintptr(fds[0]), name+"-c"), nil
}

// CloseExecFrom sets the O_CLOEXEC flag on all file descriptors greater or
// equal to minFd in the current process.
func CloseExecFrom(minFd int) error {
	return fdRangeFrom(minFd, unix.CloseOnExec)
}
