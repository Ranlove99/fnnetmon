//go:build !linux

package main

// 非 Linux 平台（开发机 macOS）没有 AF_PACKET，保留接口让编译通过。
// 域名归因在这类机器上不工作，但单元测试只测纯解析逻辑，不受影响。

type dnsSniffer struct {
	cache *DomainCache
}

func startDNSSniffer(c *DomainCache) *dnsSniffer {
	c.setState(false, "", "域名归因仅支持 Linux（AF_PACKET）")
	return &dnsSniffer{cache: c}
}

func (s *dnsSniffer) Stop() {}
