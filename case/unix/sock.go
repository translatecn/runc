package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func main() {
	parent, child, _ := NewSockPair("x")
	parent.Write([]byte("hello world"))
	buf := make([]byte, 1024)
	n, _ := child.Read(buf)
	fmt.Println(string(buf[:n]))

	child.Write([]byte("xxxxx"))
	n, _ = parent.Read(buf)
	fmt.Println(string(buf[:n]))
}

// NewSockPair returns a new unix socket pair
func NewSockPair(name string) (parent *os.File, child *os.File, err error) {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), name+"-p"), os.NewFile(uintptr(fds[0]), name+"-c"), nil
}
