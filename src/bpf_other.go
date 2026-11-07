//go:build !linux

package main

func testBPFSyscall() (bool, string) {
	return false, "当前平台不是 Linux，无法测试 bpf 系统调用"
}
