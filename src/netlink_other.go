//go:build !linux

package main

// DumpSockets 在非 Linux 平台没有实现（开发机自测用）。
func DumpSockets() ([]SockConn, error) { return nil, nil }
