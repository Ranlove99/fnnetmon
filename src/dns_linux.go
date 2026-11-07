//go:build linux

package main

import (
	"sync"
	"syscall"
	"time"
)

// AF_PACKET 抓 DNS 应答。
//
// 为什么用 SOCK_DGRAM 而不是 SOCK_RAW：SOCK_DGRAM 会把链路层头剥掉，
// 直接从 IP 头开始，省掉「以太网 / VLAN / PPPoE 头多长」这类判断。
// 万一某些环境下没剥干净，handle() 里用版本号（b[0]>>4）兜底，解析不出来就丢。
//
// 不 bind 任何网卡：未绑定的 packet socket 会收到所有网卡上的包，
// 这样新增网卡、docker bridge 都不需要重新初始化。

// PACKET_IGNORE_OUTGOING 在 syscall 包里没有导出，只能自己写常量。
const packetIgnoreOutgoing = 23

type dnsSniffer struct {
	cache *DomainCache
	fd    int
	once  sync.Once
	done  chan struct{}
}

func startDNSSniffer(c *DomainCache) *dnsSniffer {
	s := &dnsSniffer{cache: c, fd: -1, done: make(chan struct{})}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons16(syscall.ETH_P_ALL)))
	if err != nil {
		msg := "AF_PACKET 打开失败（需要 CAP_NET_RAW）：" + err.Error()
		c.setState(false, "", msg)
		c.logErr("%s", msg)
		return s
	}

	// 和 netlink 一样的教训：不设接收超时，Recvfrom 会永久阻塞，
	// 整个 goroutine 卡死且没有任何报错，从外面看就是「域名一直是空的」。
	tv := syscall.Timeval{Sec: 1}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_PACKET, packetIgnoreOutgoing, 1)

	s.fd = fd
	c.setState(true, "AF_PACKET · 监听 53 端口应答", "")
	go s.loop()
	return s
}

func (s *dnsSniffer) loop() {
	buf := make([]byte, 4096)
	for {
		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				select {
				case <-s.done:
					return
				default:
					continue
				}
			}
			select {
			case <-s.done:
				return
			default:
			}
			s.cache.logErr("recvfrom: %v", err)
			return
		}
		if n <= 0 {
			continue
		}
		s.handle(buf[:n])
	}
}

func (s *dnsSniffer) handle(b []byte) {
	if len(b) < 1 {
		return
	}
	s.cache.notePacket()

	// SOCK_DGRAM 正常情况下已经把链路层头剥掉了，但某些虚拟网卡/VLAN 环境下
	// 不一定，这里按候选偏移找 IP 头。找不到就丢，不会误判成 IP 包继续往下走。
	off0 := -1
	for _, cand := range []int{0, 14, 18, 22} {
		if len(b) > cand {
			v := b[cand] >> 4
			if v == 4 || v == 6 {
				off0 = cand
				break
			}
		}
	}
	if off0 < 0 {
		return
	}
	b = b[off0:]

	var off int
	var proto uint8
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return
		}
		proto = b[9]
		off = ihl
	case 6:
		if len(b) < 40 {
			return
		}
		proto = b[6]
		off = 40
	default:
		return
	}
	if proto != 17 { // 只处理 UDP。TCP DNS 在真实网络里占比极低，不值得为它加重组逻辑
		return
	}
	if len(b) < off+8 {
		return
	}
	sport := int(b[off])<<8 | int(b[off+1])
	dport := int(b[off+2])<<8 | int(b[off+3])
	ulen := int(b[off+4])<<8 | int(b[off+5])
	if sport != 53 && dport != 53 {
		return
	}
	if ulen < 8 || off+ulen > len(b) {
		return
	}
	if obs, ok := parseDNSMessage(b[off+8 : off+ulen]); ok {
		s.cache.Observe(obs, time.Now().Unix())
	}
}

func (s *dnsSniffer) Stop() {
	s.once.Do(func() {
		close(s.done)
		if s.fd >= 0 {
			_ = syscall.Close(s.fd)
		}
		s.cache.setState(false, "", "")
	})
}

func htons16(v uint16) uint16 { return v<<8 | v>>8 }
