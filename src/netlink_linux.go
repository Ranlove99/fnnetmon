//go:build linux

package main

import (
	"encoding/binary"
	"syscall"
)

const (
	netlinkSockDiag  = 4
	sockDiagByFamily = 20
	nlmFRequest      = 0x1
	nlmFDump         = 0x300
	nlmsgDone        = 3
	nlmsgError       = 2
)

// DumpSockets 通过 NETLINK_SOCK_DIAG 一次性 dump 全部 TCP/UDP socket，
// 并带上 INET_DIAG_INFO（tcp_info），从中读取累计收发字节。
// 这比挂 eBPF kprobe 简单，也不会漏掉内核态直接发送的数据。
func DumpSockets() ([]SockConn, error) {
	var out []SockConn
	for _, spec := range []struct {
		family  uint8
		proto   uint8
		name    string
		withBuf bool
	}{
		{syscall.AF_INET, syscall.IPPROTO_TCP, "tcp", true},
		{syscall.AF_INET6, syscall.IPPROTO_TCP, "tcp6", true},
		{syscall.AF_INET, syscall.IPPROTO_UDP, "udp", false},
		{syscall.AF_INET6, syscall.IPPROTO_UDP, "udp6", false},
	} {
		conns, err := diagDump(spec.family, spec.proto, spec.name, spec.withBuf)
		if err != nil {
			continue
		}
		out = append(out, conns...)
	}
	return out, nil
}

func diagDump(family, proto uint8, name string, withBuf bool) ([]SockConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkSockDiag)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	sa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, sa); err != nil {
		return nil, err
	}
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	// 必须设接收超时。没有它的话，内核一旦不返回 NLMSG_DONE，
	// Recvfrom 会永久阻塞，把 1 秒一次的采集循环整个卡死——进程还活着，但页面不再更新。
	tv := syscall.Timeval{Sec: 2}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// nlmsghdr(16) + inet_diag_req_v2(56)
	req := make([]byte, 72)
	binary.LittleEndian.PutUint32(req[0:], 72) // nlmsg_len
	binary.LittleEndian.PutUint16(req[4:], sockDiagByFamily)
	binary.LittleEndian.PutUint16(req[6:], nlmFRequest|nlmFDump)
	binary.LittleEndian.PutUint32(req[8:], 1)  // seq
	binary.LittleEndian.PutUint32(req[12:], 0) // pid

	req[16] = family
	req[17] = proto
	if withBuf {
		req[18] = 1 << (inetDiagInfo - 1) // idiag_ext = 1<<1
	}
	binary.LittleEndian.PutUint32(req[20:], 0xFFFFFFFF) // idiag_states: all

	if err := syscall.Sendto(fd, req, 0, sa); err != nil {
		return nil, err
	}

	buf := make([]byte, 1<<16)
	out := make([]SockConn, 0, 256)
	// 加迭代上限：正常情况下 NLMSG_DONE 很快就到，
	// 但如果内核一直吐数据不给 DONE，这里必须能自己停下来。
	for iter := 0; iter < 512; iter++ {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			break
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			break
		}
		done := false
		for _, m := range msgs {
			switch m.Header.Type {
			case nlmsgDone:
				done = true
			case nlmsgError:
				done = true
			case sockDiagByFamily:
				if c, ok := parseDiagMsg(m.Data, name); ok {
					out = append(out, c)
				}
			}
		}
		if done {
			break
		}
	}
	return out, nil
}
