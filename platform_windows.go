//go:build windows

package main

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func defaultConfigPath() string {
	return "rules.yaml"
}

func enableANSI() {
	hOut := windows.Stdout
	var mode uint32
	if err := windows.GetConsoleMode(hOut, &mode); err == nil {
		_ = windows.SetConsoleMode(hOut, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
	}
}

func relaunchAsAdmin() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()

	var args []string
	for _, a := range os.Args[1:] {
		if a != "--elevate" && a != "-elevate" {
			args = append(args, a)
		}
	}
	argStr := strings.Join(args, " ")

	verbPtr, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exe)
	argPtr, _ := windows.UTF16PtrFromString(argStr)
	cwdPtr, _ := windows.UTF16PtrFromString(cwd)

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, windows.SW_SHOWNORMAL)
}
