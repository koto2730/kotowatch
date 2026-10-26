//go:build darwin || linux

package main

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

func defaultConfigPath() string {
	switch runtime.GOOS {
	case "darwin":
		if _, err := os.Stat("rules.macos.yaml"); err == nil {
			return "rules.macos.yaml"
		}
	case "linux":
		if _, err := os.Stat("rules.linux.yaml"); err == nil {
			return "rules.linux.yaml"
		}
	}
	return "rules.yaml"
}

func enableANSI() {
	// macOS / Linux terminals natively support ANSI escape sequences.
}

func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return err
	}

	args := []string{"sudo", exe}
	for _, a := range os.Args[1:] {
		if a != "--elevate" && a != "-elevate" {
			args = append(args, a)
		}
	}
	return syscall.Exec(sudoPath, args, os.Environ())
}
