//go:build !linux

package main

import (
	"os/exec"
	"strings"
)

func uname() (string, string, string) {
	out, err := exec.Command("uname", "-s", "-r", "-m").Output()
	if err != nil {
		return "", "", ""
	}
	f := strings.Fields(string(out))
	for len(f) < 3 {
		f = append(f, "")
	}
	return f[0], f[1], f[2]
}
