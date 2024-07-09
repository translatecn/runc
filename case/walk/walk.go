package main

import (
	"fmt"
	"io/fs"
	"path/filepath"
)

func main() {
	filepath.WalkDir("/Users/acejilam/Desktop/todo/runc", func(path string, d fs.DirEntry, err error) error {
		fmt.Println(path)
		return nil
	})

}
