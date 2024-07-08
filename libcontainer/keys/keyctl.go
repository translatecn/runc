package keys

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type KeySerial uint32

// ModKeyringPerm modifies permissions on a keyring by reading the current permissions,
// anding the bits with the given mask (clearing permissions) and setting
// additional permission bits
func ModKeyringPerm(ringID KeySerial, mask, setbits uint32) error {
	dest, err := unix.KeyctlString(unix.KEYCTL_DESCRIBE, int(ringID))
	if err != nil {
		return err
	}

	res := strings.Split(dest, ";") // keyring;0;0;3f130000;_ses.f071e69bd1243fab9c297854ef5ad35fc7d0a8049bd2214f4dfdeb2abefd9d76
	if len(res) < 5 {
		return errors.New("Destination buffer for key description is too small")
	}

	// parse permissions
	perm64, err := strconv.ParseUint(res[3], 16, 32)
	if err != nil {
		return err
	}

	perm := (uint32(perm64) & mask) | setbits

	return unix.KeyctlSetperm(int(ringID), perm)
}
func JoinSessionKeyring(name string) (KeySerial, error) {
	sessKeyID, err := unix.KeyctlJoinSessionKeyring(name)
	if err != nil {
		return 0, fmt.Errorf("unable to create session key: %w", err)
	}
	return KeySerial(sessKeyID), nil
}
