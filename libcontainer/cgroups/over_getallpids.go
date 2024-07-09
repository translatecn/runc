package cgroups

import (
	"io/fs"
	"path/filepath"
)

func GetAllPids(path string) ([]int, error) {
	var pids []int
	err := filepath.WalkDir(path, func(p string, d fs.DirEntry, iErr error) error {
		if iErr != nil {
			return iErr
		}
		if !d.IsDir() {
			return nil
		}
		cPids, err := readProcsFile(p)
		if err != nil {
			return err
		}
		pids = append(pids, cPids...)
		return nil
	})
	return pids, err
}
