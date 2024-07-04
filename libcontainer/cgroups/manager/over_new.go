package manager

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs"
	"github.com/opencontainers/runc/libcontainer/cgroups/fs2"
	"github.com/opencontainers/runc/libcontainer/cgroups/systemd"
	"github.com/opencontainers/runc/libcontainer/configs"
)

// NewWithPaths 函数类似于New，可以在已知cgroup路径的情况下使用，以节省一些资源。
// 对于cgroup v1，键是控制器/子系统名称，值是指向相应cgroup的绝对文件系统路径。
// 对于cgroup v2，只允许一个键（空字符串），其值是统一的cgroup路径。
func NewWithPaths(config *configs.Cgroup, paths map[string]string) (cgroups.Manager, error) {
	if config == nil {
		return nil, errors.New("cgroups/manager.New: config must not be nil")
	}
	if config.Systemd && !systemd.IsRunningSystemd() {
		return nil, errors.New("systemd not running on this host, cannot use systemd cgroups manager")
	}

	// Cgroup v2 aka unified hierarchy.
	if cgroups.IsCgroup2UnifiedMode() {
		path, err := getUnifiedPath(paths)
		if err != nil {
			return nil, fmt.Errorf("manager.NewWithPaths: inconsistent paths: %w", err)
		}
		if config.Systemd {
			return systemd.NewUnifiedManager(config, path)
		}
		return fs2.NewManager(config, path)
	}

	// Cgroup v1.
	if config.Systemd {
		return systemd.NewLegacyManager(config, paths)
	}

	return fs.NewManager(config, paths)
}

// getUnifiedPath is an implementation detail of libcontainer factory.
// Historically, it saves cgroup paths as per-subsystem path map (as returned
// by cm.GetPaths(""), but with v2 we only have one single unified path
// (with "" as a key).
//
// This function converts from that map to string (using "" as a key),
// and also checks that the map itself is sane.
func getUnifiedPath(paths map[string]string) (string, error) {
	if len(paths) > 1 {
		return "", fmt.Errorf("expected a single path, got %+v", paths)
	}
	path := paths[""]
	// can be empty
	if path != "" {
		if filepath.Clean(path) != path || !filepath.IsAbs(path) {
			return "", fmt.Errorf("invalid path: %q", path)
		}
	}

	return path, nil
}

// New returns the instance of a cgroup manager, which is chosen
// based on the local environment (whether cgroup v1 or v2 is used)
// and the config (whether config.Systemd is set or not).
func New(config *configs.Cgroup) (cgroups.Manager, error) {
	return NewWithPaths(config, nil)
}
