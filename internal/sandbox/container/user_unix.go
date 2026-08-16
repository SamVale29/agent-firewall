//go:build !windows

package container

import (
	"fmt"
	"os"
)

func containerUser() string { return fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()) }
