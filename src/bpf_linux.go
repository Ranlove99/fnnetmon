//go:build linux

package main

import (
	"syscall"
	"unsafe"
)

type bpfMapCreateAttr struct {
	MapType               uint32
	KeySize               uint32
	ValueSize             uint32
	MaxEntries            uint32
	MapFlags              uint32
	InnerMapFd            uint32
	NumaNode              uint32
	MapName               [16]byte
	MapIfindex            uint32
	BtfFd                 uint32
	BtfKeyTypeId          uint32
	BtfValueTypeId        uint32
	BtfVmlinuxValueTypeId uint32
	MapExtra              uint64
}

const (
	bpfMapCreate    = 0
	bpfMapTypeArray = 2
)

// testBPFSyscall 直接调 bpf(2) 建一个最小 map，是最可靠的能力探针：
// 成功 = 内核开了 CONFIG_BPF_SYSCALL 且当前身份有 CAP_BPF。
func testBPFSyscall() (bool, string) {
	attr := bpfMapCreateAttr{
		MapType:    bpfMapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	fd, _, errno := syscall.Syscall(sysBPF, uintptr(bpfMapCreate),
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if errno == 0 && int(fd) >= 0 {
		syscall.Close(int(fd))
		return true, "BPF_MAP_CREATE 成功"
	}
	switch errno {
	case syscall.ENOSYS:
		return false, "内核未提供 bpf 系统调用 (CONFIG_BPF_SYSCALL=n)"
	case syscall.EPERM, syscall.EACCES:
		return false, "bpf 系统调用被拒绝: " + errno.Error()
	case syscall.EINVAL:
		return true, "bpf 系统调用存在（参数被拒，通常说明能力正常）"
	default:
		return false, "BPF_MAP_CREATE 失败: " + errno.Error()
	}
}
