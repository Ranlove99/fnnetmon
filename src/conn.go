package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// TCP 状态常量（与内核 uapi 一致）
const (
	tcpEstablished = 1
	tcpSynSent     = 2
	tcpSynRecv     = 3
	tcpFinWait1    = 4
	tcpFinWait2    = 5
	tcpTimeWait    = 6
	tcpClose       = 7
	tcpCloseWait   = 8
	tcpLastAck     = 9
	tcpListen      = 10
	tcpClosing     = 11
)

// SockConn 是一条内核 socket 的当前状态。
type SockConn struct {
	Proto      string
	Family     uint8
	State      uint8
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	UID        uint32
	Inode      uint32
	TxBytes    uint64 // tcp_info.tcpi_bytes_acked
	RxBytes    uint64 // tcp_info.tcpi_bytes_received
	HasBytes   bool   // UDP 没有字节计数
	RTT        uint32
	Retrans    uint32
}

func tcpStateName(s uint8) string {
	switch s {
	case tcpEstablished:
		return "ESTABLISHED"
	case tcpSynSent:
		return "SYN_SENT"
	case tcpSynRecv:
		return "SYN_RECV"
	case tcpFinWait1:
		return "FIN_WAIT1"
	case tcpFinWait2:
		return "FIN_WAIT2"
	case tcpTimeWait:
		return "TIME_WAIT"
	case tcpClose:
		return "CLOSE"
	case tcpCloseWait:
		return "CLOSE_WAIT"
	case tcpLastAck:
		return "LAST_ACK"
	case tcpListen:
		return "LISTEN"
	case tcpClosing:
		return "CLOSING"
	}
	return fmt.Sprintf("STATE_%d", s)
}

const inetDiagInfo = 2

// inet_diag_msg 固定 72 字节，其后是 rtattr 列表。
func parseDiagMsg(b []byte, name string) (SockConn, bool) {
	if len(b) < 72 {
		return SockConn{}, false
	}
	c := SockConn{Proto: name, Family: b[0], State: b[1]}

	sport := binary.BigEndian.Uint16(b[4:])
	dport := binary.BigEndian.Uint16(b[6:])
	src := b[8:24]
	dst := b[24:40]
	if c.Family == syscall.AF_INET {
		c.LocalIP = net.IP(src[:4]).String()
		c.RemoteIP = net.IP(dst[:4]).String()
	} else {
		c.LocalIP = net.IP(src).String()
		c.RemoteIP = net.IP(dst).String()
	}
	c.LocalPort = sport
	c.RemotePort = dport

	c.UID = binary.LittleEndian.Uint32(b[64:])
	c.Inode = binary.LittleEndian.Uint32(b[68:])

	// 解析属性，找 INET_DIAG_INFO
	off := 72
	for off+4 <= len(b) {
		rlen := int(binary.LittleEndian.Uint16(b[off:]))
		rtype := int(binary.LittleEndian.Uint16(b[off+2:]))
		if rlen < 4 || off+rlen > len(b) {
			break
		}
		if rtype == inetDiagInfo {
			payload := b[off+4 : off+rlen]
			// tcp_info: bytes_acked @120, bytes_received @128, rtt @68, total_retrans @100
			if len(payload) >= 136 {
				c.TxBytes = binary.LittleEndian.Uint64(payload[120:])
				c.RxBytes = binary.LittleEndian.Uint64(payload[128:])
				c.HasBytes = true
			}
			if len(payload) >= 72 {
				c.RTT = binary.LittleEndian.Uint32(payload[68:])
			}
			if len(payload) >= 104 {
				c.Retrans = binary.LittleEndian.Uint32(payload[100:])
			}
		}
		off += (rlen + 3) &^ 3
	}
	return c, true
}
