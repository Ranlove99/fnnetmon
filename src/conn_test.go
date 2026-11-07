package main

import (
	"encoding/binary"
	"net"
	"testing"
)

// buildDiagMsg 按内核 uapi 的布局构造一条 inet_diag_msg，
// 用来锁死字段偏移——这类代码写错一个字节就会静默失效。
func buildDiagMsg(t *testing.T, family uint8, state uint8, sip, dip string, sport, dport uint16,
	uid, inode uint32, acked, received uint64, rtt, retrans uint32) []byte {

	t.Helper()
	b := make([]byte, 72)
	b[0] = family
	b[1] = state
	binary.BigEndian.PutUint16(b[4:], sport)
	binary.BigEndian.PutUint16(b[6:], dport)

	if family == 2 { // AF_INET
		copy(b[8:12], net.ParseIP(sip).To4())
		copy(b[24:28], net.ParseIP(dip).To4())
	} else {
		copy(b[8:24], net.ParseIP(sip).To16())
		copy(b[24:40], net.ParseIP(dip).To16())
	}

	binary.LittleEndian.PutUint32(b[52:], 0)     // idiag_expires
	binary.LittleEndian.PutUint32(b[56:], 0)     // idiag_rqueue
	binary.LittleEndian.PutUint32(b[60:], 0)     // idiag_wqueue
	binary.LittleEndian.PutUint32(b[64:], uid)   // idiag_uid
	binary.LittleEndian.PutUint32(b[68:], inode) // idiag_inode

	// INET_DIAG_INFO 属性：rta_len(2) + rta_type(2) + tcp_info
	ti := make([]byte, 240)
	binary.LittleEndian.PutUint32(ti[68:], rtt)
	binary.LittleEndian.PutUint32(ti[100:], retrans)
	binary.LittleEndian.PutUint64(ti[120:], acked)
	binary.LittleEndian.PutUint64(ti[128:], received)

	attr := make([]byte, 4+len(ti))
	binary.LittleEndian.PutUint16(attr[0:], uint16(len(attr)))
	binary.LittleEndian.PutUint16(attr[2:], inetDiagInfo)
	copy(attr[4:], ti)

	return append(b, attr...)
}

func TestParseDiagMsgIPv4(t *testing.T) {
	msg := buildDiagMsg(t, 2, tcpEstablished, "192.168.1.118", "142.250.66.14", 44321, 443,
		1000, 987654, 123456789, 987654321, 12000, 3)

	c, ok := parseDiagMsg(msg, "tcp")
	if !ok {
		t.Fatal("parse failed")
	}
	if c.LocalIP != "192.168.1.118" || c.LocalPort != 44321 {
		t.Errorf("local = %s:%d", c.LocalIP, c.LocalPort)
	}
	if c.RemoteIP != "142.250.66.14" || c.RemotePort != 443 {
		t.Errorf("remote = %s:%d", c.RemoteIP, c.RemotePort)
	}
	if c.UID != 1000 {
		t.Errorf("uid = %d, want 1000", c.UID)
	}
	if c.Inode != 987654 {
		t.Errorf("inode = %d, want 987654", c.Inode)
	}
	if !c.HasBytes {
		t.Error("HasBytes = false")
	}
	if c.TxBytes != 123456789 {
		t.Errorf("tx = %d, want 123456789", c.TxBytes)
	}
	if c.RxBytes != 987654321 {
		t.Errorf("rx = %d, want 987654321", c.RxBytes)
	}
	if c.RTT != 12000 {
		t.Errorf("rtt = %d, want 12000", c.RTT)
	}
	if c.Retrans != 3 {
		t.Errorf("retrans = %d, want 3", c.Retrans)
	}
	if got := tcpStateName(c.State); got != "ESTABLISHED" {
		t.Errorf("state = %s", got)
	}
}

func TestParseDiagMsgIPv6(t *testing.T) {
	msg := buildDiagMsg(t, 10, tcpTimeWait, "fe80::1", "2400:3200::1", 50000, 80, 0, 42, 10, 20, 0, 0)
	c, ok := parseDiagMsg(msg, "tcp6")
	if !ok {
		t.Fatal("parse failed")
	}
	if c.LocalIP != "fe80::1" {
		t.Errorf("local = %s", c.LocalIP)
	}
	if c.RemoteIP != "2400:3200::1" {
		t.Errorf("remote = %s", c.RemoteIP)
	}
	if c.Inode != 42 {
		t.Errorf("inode = %d", c.Inode)
	}
	if tcpStateName(c.State) != "TIME_WAIT" {
		t.Errorf("state = %s", tcpStateName(c.State))
	}
}

// UDP 不带 INET_DIAG_INFO，必须标记 HasBytes=false，避免把 0 当成真实字节数。
func TestParseDiagMsgNoInfo(t *testing.T) {
	b := make([]byte, 72)
	b[0] = 2
	b[1] = 7
	binary.BigEndian.PutUint16(b[4:], 53)
	binary.LittleEndian.PutUint32(b[68:], 777)
	c, ok := parseDiagMsg(b, "udp")
	if !ok {
		t.Fatal("parse failed")
	}
	if c.HasBytes {
		t.Error("UDP 不应有字节计数")
	}
	if c.Inode != 777 {
		t.Errorf("inode = %d, want 777", c.Inode)
	}
}

func TestParseDiagMsgTruncated(t *testing.T) {
	if _, ok := parseDiagMsg(make([]byte, 10), "tcp"); ok {
		t.Error("短包应被拒绝")
	}
}
