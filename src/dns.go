package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 本文件负责「域名归因」：把 IP 还原成用户认识的域名。
//
// 路线选择（v0.5.0 起）：不用 TC eBPF 抓 TLS SNI，改成 AF_PACKET 抓 DNS 应答。
// 理由是成本差两个数量级，而且覆盖面更广：
//   - eBPF 要 clang 交叉编译、要 attach tc hook、只认 TLS；
//   - DNS 应答只要解析报文，HTTP/QUIC/MQTT/私有协议全都能归因。
//
// 代价是 DoH/DoT 用户的解析请求不经过网卡，这部分归因不到。
// 这是已知缺口，宁可按「大部分可见」交付，也不为了 100% 覆盖把复杂度翻倍。
//
// 本文件只做报文解析和缓存，socket 在 dns_linux.go 里，方便在 macOS 上跑单测。

// dnsObservation 是一条解析结果。
type dnsObservation struct {
	Question string
	IPs      []string
	TTL      uint32
}

// parseDNSMessage 从一段 UDP 载荷里抽出「问题域名 + 所有 A/AAAA 答案」。
//
// 只接受「标准查询的应答、无错误码」这一种报文。任何畸形字段一律返回 false，
// 绝不 panic —— 这段代码直接吃网卡上的原始字节，来源不可信。
func parseDNSMessage(b []byte) (obs dnsObservation, ok bool) {
	if len(b) < 12 {
		return obs, false
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	if flags>>15 != 1 { // QR=0 是查询，不要
		return obs, false
	}
	if (flags>>11)&0xF != 0 { // opcode 只认标准查询
		return obs, false
	}
	if flags&0xF != 0 { // rcode 非 0，域名不存在之类，跳过
		return obs, false
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	an := int(binary.BigEndian.Uint16(b[6:8]))
	if qd < 1 || an < 1 || an > 64 {
		return obs, false
	}

	name, next, okName := dnsSkipName(b, 12)
	if !okName || name == "" {
		return obs, false
	}
	// question 后面还有 type(2) + class(2)
	off := next + 4
	if off > len(b) {
		return obs, false
	}

	seen := map[string]bool{}
	var minTTL uint32
	for i := 0; i < an; i++ {
		_, no, okN := dnsSkipName(b, off)
		if !okN {
			break
		}
		off = no
		if off+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[off:])
		class := binary.BigEndian.Uint16(b[off+2:])
		ttl := binary.BigEndian.Uint32(b[off+4:])
		rdlen := int(binary.BigEndian.Uint16(b[off+8:]))
		off += 10
		if rdlen < 0 || off+rdlen > len(b) {
			break
		}
		rdata := b[off : off+rdlen]
		off += rdlen

		if class != 1 { // IN
			continue
		}
		var ip string
		switch typ {
		case 1: // A
			if rdlen == 4 {
				ip = net.IP(rdata).String()
			}
		case 28: // AAAA
			if rdlen == 16 {
				ip = net.IP(rdata).String()
			}
		}
		if ip == "" {
			continue
		}
		if !seen[ip] {
			seen[ip] = true
			obs.IPs = append(obs.IPs, ip)
		}
		if minTTL == 0 || ttl < minTTL {
			minTTL = ttl
		}
	}
	if len(obs.IPs) == 0 {
		return obs, false
	}
	obs.Question = normalizeDomain(name)
	obs.TTL = minTTL
	return obs, true
}

// dnsSkipName 解析域名，返回域名和「这个名字之后」的偏移。
// 必须处理压缩指针（0xC0），否则应答里的 answer name 全是指针，直接解析会失败。
func dnsSkipName(b []byte, off int) (string, int, bool) {
	var sb strings.Builder
	next := -1
	jumps := 0
	for {
		if off < 0 || off >= len(b) {
			return "", 0, false
		}
		l := int(b[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(b) {
				return "", 0, false
			}
			ptr := int(b[off]&0x3F)<<8 | int(b[off+1])
			if next < 0 {
				next = off + 2
			}
			jumps++
			// 指针成环是攻击面，限制跳转次数
			if jumps > 16 || ptr >= len(b) {
				return "", 0, false
			}
			off = ptr
			continue
		}
		if l&0xC0 != 0 { // 0x40/0x80 是保留类型
			return "", 0, false
		}
		if off+1+l > len(b) {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[off+1 : off+1+l])
		off += 1 + l
		if sb.Len() > 253 {
			return "", 0, false
		}
	}
	if next < 0 {
		next = off
	}
	return sb.String(), next, true
}

func normalizeDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.TrimSuffix(s, ".")
}

// ---- 缓存 ----

type ipDomain struct {
	Name   string // 最早见到的域名
	Extra  int    // 同一个 IP 上还见过多少个别的域名（CDN 场景）
	Expire int64
}

type domainIPs struct {
	IPs    map[string]bool
	Expire int64
}

// DomainCache 维护 IP→域名 和 域名→IP 两张表。
//
// 两张表都要：前者用来在界面上把 104.16.x.x 显示成 cloudflare.com，
// 后者用来把「封 example.com」翻译成 nft 里的一组 daddr。
type DomainCache struct {
	mu       sync.RWMutex
	byIP     map[string]*ipDomain
	byDomain map[string]*domainIPs

	maxIP  int
	maxDom int

	packets  int64 // 收到的 DNS 报文数
	answered int64 // 解析成功的应答数
	lastAt   int64
	lastQ    string
	err      string
	src      string // 抓包来源描述，给界面显示
	running  bool
}

const (
	defaultMaxIP  = 8192
	defaultMaxDom = 4096
	maxDomainTTL  = 3600
	minDomainTTL  = 60
)

func NewDomainCache() *DomainCache {
	return &DomainCache{
		byIP:     map[string]*ipDomain{},
		byDomain: map[string]*domainIPs{},
		maxIP:    defaultMaxIP,
		maxDom:   defaultMaxDom,
	}
}

// Observe 记录一条抓到的解析结果。
func (c *DomainCache) Observe(obs dnsObservation, now int64) {
	c.observe(obs, now, true)
}

// observe 是内部实现。count=false 用于主动解析（Seed），
// 否则「DNS 应答数」会把我们自己发起的查询也算进去，和报文数对不上。
func (c *DomainCache) observe(obs dnsObservation, now int64, count bool) {
	if obs.Question == "" || len(obs.IPs) == 0 {
		return
	}
	ttl := obs.TTL
	if ttl < minDomainTTL {
		ttl = minDomainTTL
	}
	if ttl > maxDomainTTL {
		ttl = maxDomainTTL
	}
	exp := now + int64(ttl)

	c.mu.Lock()
	defer c.mu.Unlock()
	if count {
		c.answered++
	}
	c.lastAt = now
	c.lastQ = obs.Question

	d := c.byDomain[obs.Question]
	if d == nil {
		if len(c.byDomain) >= c.maxDom {
			c.evictDomainLocked()
		}
		d = &domainIPs{IPs: map[string]bool{}}
		c.byDomain[obs.Question] = d
	}
	d.Expire = exp
	for _, ip := range obs.IPs {
		d.IPs[ip] = true
		e := c.byIP[ip]
		if e == nil {
			if len(c.byIP) >= c.maxIP {
				c.evictIPLocked()
			}
			e = &ipDomain{Name: obs.Question}
			c.byIP[ip] = e
		} else if e.Name != obs.Question {
			// 同一个 IP 被多个域名解析到（CDN 常态），保留最早的，
			// 另外记一个计数，界面显示「a.com 等 3 个域名」
			e.Extra++
			if e.Extra > 99 {
				e.Extra = 99
			}
		}
		e.Expire = exp
	}
}

func (c *DomainCache) evictIPLocked() {
	// 过期时间最早的先扔。全表扫描只在超上限时发生，条目数有上限，开销可控。
	var oldestKey string
	var oldest int64 = 1<<62 - 1
	for k, v := range c.byIP {
		if v.Expire < oldest {
			oldest, oldestKey = v.Expire, k
		}
	}
	if oldestKey != "" {
		delete(c.byIP, oldestKey)
	}
}

func (c *DomainCache) evictDomainLocked() {
	var oldestKey string
	var oldest int64 = 1<<62 - 1
	for k, v := range c.byDomain {
		if v.Expire < oldest {
			oldest, oldestKey = v.Expire, k
		}
	}
	if oldestKey != "" {
		delete(c.byDomain, oldestKey)
	}
}

// Lookup 查 IP 对应的域名，返回名字和「另外还见过几个域名」。
func (c *DomainCache) Lookup(ip string, now int64) (string, int) {
	if ip == "" {
		return "", 0
	}
	c.mu.RLock()
	e := c.byIP[ip]
	if e == nil || e.Expire < now {
		c.mu.RUnlock()
		return "", 0
	}
	name, extra := e.Name, e.Extra
	c.mu.RUnlock()
	return name, extra
}

// IPsFor 返回某个域名当前已知的地址。域名规则下发时用。
func (c *DomainCache) IPsFor(domain string, now int64) []string {
	domain = normalizeDomain(domain)
	c.mu.RLock()
	d := c.byDomain[domain]
	if d == nil || d.Expire < now {
		c.mu.RUnlock()
		return nil
	}
	out := make([]string, 0, len(d.IPs))
	for ip := range d.IPs {
		out = append(out, ip)
	}
	c.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Seed 从一次主动解析的结果填充缓存（域名规则的首次下发用）。
func (c *DomainCache) Seed(domain string, ips []string, ttl uint32) {
	c.observe(dnsObservation{Question: normalizeDomain(domain), IPs: ips, TTL: ttl}, time.Now().Unix(), false)
}

// Prune 清理过期条目。由 Hub 每 30 秒顺带调一次。
func (c *DomainCache) Prune(now int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.byIP {
		if v.Expire < now {
			delete(c.byIP, k)
		}
	}
	for k, v := range c.byDomain {
		if v.Expire < now {
			delete(c.byDomain, k)
		}
	}
}

// Resolve 主动解析一个域名并写回缓存。
//
// 只在「用户新建域名规则」时调用一次，不在采集循环里用 ——
// net.LookupHost 是阻塞的，塞进 tick 会直接把采集卡死。
func (c *DomainCache) Resolve(domain string) ([]string, error) {
	domain = normalizeDomain(domain)
	if domain == "" {
		return nil, fmt.Errorf("空域名")
	}
	if !validDomain(domain) {
		return nil, fmt.Errorf("非法域名：%s", domain)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}
	if len(ips) > 0 {
		c.Seed(domain, ips, 300)
	}
	return ips, nil
}

// validDomain 严格校验域名，拼进 nft 之前必须过这一关。
func validDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
			if !ok {
				return false
			}
		}
	}
	return true
}

type DomainStats struct {
	Running  bool   `json:"running"`
	Source   string `json:"src"`
	Error    string `json:"err,omitempty"`
	Packets  int64  `json:"packets"`
	Answered int64  `json:"answered"`
	IPs      int    `json:"ips"`
	Domains  int    `json:"domains"`
	LastAt   int64  `json:"last_at"`
	LastQ    string `json:"last_q"`
}

func (c *DomainCache) Stats() DomainStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return DomainStats{
		Running:  c.running,
		Source:   c.src,
		Error:    c.err,
		Packets:  c.packets,
		Answered: c.answered,
		IPs:      len(c.byIP),
		Domains:  len(c.byDomain),
		LastAt:   c.lastAt,
		LastQ:    c.lastQ,
	}
}

func (c *DomainCache) notePacket() {
	c.mu.Lock()
	c.packets++
	c.mu.Unlock()
}

func (c *DomainCache) setState(running bool, src, errMsg string) {
	c.mu.Lock()
	c.running, c.src, c.err = running, src, errMsg
	c.mu.Unlock()
}

func (c *DomainCache) logErr(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[fnnetmon] dns: "+format+"\n", args...)
}
