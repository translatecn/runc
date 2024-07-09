package fs

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"time"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
	"golang.org/x/sys/unix"
)

type FreezerGroup struct{}

func (s *FreezerGroup) Name() string {
	return "freezer"
}

func (s *FreezerGroup) Apply(path string, _ *configs.Resources, pid int) error {
	return apply(path, pid)
}

func (s *FreezerGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}

func (s *FreezerGroup) GetState(path string) (configs.FreezerState, error) {
	for {
		state, err := cgroups.ReadFile(path, "freezer.state")
		if err != nil {
			// If the kernel is too old, then we just treat the freezer as
			// being in an "undefined" state.
			if os.IsNotExist(err) || errors.Is(err, unix.ENODEV) {
				err = nil
			}
			return configs.Undefined, err
		}
		switch strings.TrimSpace(state) {
		case "THAWED":
			return configs.Thawed, nil
		case "FROZEN":
			// Find out whether the cgroup is frozen directly,
			// or indirectly via an ancestor.
			self, err := cgroups.ReadFile(path, "freezer.self_freezing")
			if err != nil {
				// If the kernel is too old, then we just treat
				// it as being frozen.
				if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENODEV) {
					err = nil
				}
				return configs.Frozen, err
			}
			switch self {
			case "0\n":
				return configs.Thawed, nil
			case "1\n":
				return configs.Frozen, nil
			default:
				return configs.Undefined, fmt.Errorf(`unknown "freezer.self_freezing" state: %q`, self)
			}
		case "FREEZING":
			// Make sure we get a stable freezer state, so retry if the cgroup
			// is still undergoing freezing. This should be a temporary delay.
			time.Sleep(1 * time.Millisecond)
			continue
		default:
			return configs.Undefined, fmt.Errorf("unknown freezer.state %q", state)
		}
	}
}

func (s *FreezerGroup) Set(path string, r *configs.Resources) (Err error) {
	switch r.Freezer {
	case configs.Frozen:
		defer func() {
			if Err != nil {
				// Freezing failed, and it is bad and dangerous
				// to leave the cgroup in FROZEN or FREEZING
				// state, so (try to) thaw it back.
				_ = cgroups.WriteFile(path, "freezer.state", string(configs.Thawed))
			}
		}()

		for i := 0; i < 1000; i++ {
			if i%50 == 49 {
				// Occasional thaw and sleep improves
				// the chances to succeed in freezing
				// in case new processes keep appearing
				// in the cgroup.
				_ = cgroups.WriteFile(path, "freezer.state", string(configs.Thawed))
				time.Sleep(10 * time.Millisecond)
			}

			if err := cgroups.WriteFile(path, "freezer.state", string(configs.Frozen)); err != nil {
				return err
			}

			if i%25 == 24 {
				// Occasional short sleep before reading
				// the state back also improves the chances to
				// succeed in freezing in case of a very slow
				// system.
				time.Sleep(10 * time.Microsecond)
			}
			state, err := cgroups.ReadFile(path, "freezer.state")
			if err != nil {
				return err
			}
			state = strings.TrimSpace(state)
			switch state {
			case "FREEZING":
				continue
			case string(configs.Frozen):
				if i > 1 {
					logrus.Debugf("frozen after %d retries", i)
				}
				return nil
			default:
				// should never happen
				return fmt.Errorf("unexpected state %s while freezing", strings.TrimSpace(state))
			}
		}
		// Despite our best efforts, it got stuck in FREEZING.
		return errors.New("unable to freeze")
	case configs.Thawed:
		return cgroups.WriteFile(path, "freezer.state", string(configs.Thawed))
	case configs.Undefined:
		return nil
	default:
		return fmt.Errorf("Invalid argument '%s' to freezer.state", string(r.Freezer))
	}
}
