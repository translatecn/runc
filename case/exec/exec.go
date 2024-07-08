package main

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

func main() {
	fmt.Println(os.Getpid())
	// 要执行的命令及其参数
	binary := "/usr/bin/python3"
	var args []string
	env := os.Environ()

	// 通过 Exec 执行命令
	err := unix.Exec(binary, args, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error executing command: %v\n", err)
		os.Exit(1)
	}

	// 注意：因为 exec 替换了当前进程，除非失败，否则代码不会执行到这里
	fmt.Println("This will not be outputted")

}
