//go:build linux

package main

import "syscall"

func uname() (string, string, string) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "", "", ""
	}
	cvt := func(a [65]int8) string {
		b := make([]byte, 0, 65)
		for _, c := range a {
			if c == 0 {
				break
			}
			b = append(b, byte(c))
		}
		return string(b)
	}
	return cvt(u.Sysname), cvt(u.Release), cvt(u.Machine)
}
