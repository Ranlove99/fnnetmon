package main

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

// ---- DNS 报文构造工具 ----

// buildDNSResponse 拼一个最小的 DNS 应答报文，用于测试解析器。
func buildDNSResponse(qname string, answers []struct {
	IP  []byte
	TTL uint32
	Typ uint16
}, flags uint16) []byte {
	var b []byte
	b = append(b, 0x12, 0x34)                                  // ID
	b = binary.BigEndian.AppendUint16(b, flags)                // flags
	b = binary.BigEndian.AppendUint16(b, 1)                    // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, uint16(len(answers))) // ANCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)                    // NSCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)                    // ARCOUNT

	for _, label := range strings.Split(qname, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, 1) // QTYPE A
	b = binary.BigEndian.AppendUint16(b, 1) // QCLASS IN

	for _, a := range answers {
		b = append(b, 0xC0, 0x0C) // 名字用压缩指针指回偏移 12
		b = binary.BigEndian.AppendUint16(b, a.Typ)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, a.TTL)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.IP)))
		b = append(b, a.IP...)
	}
	return b
}

func TestParseDNSResponse(t *testing.T) {
	ans := []struct {
		IP  []byte
		TTL uint32
		Typ uint16
	}{
		{[]byte{93, 184, 216, 34}, 300, 1},
		{[]byte{93, 184, 216, 35}, 120, 1},
	}
	pkt := buildDNSResponse("www.example.com", ans, 0x8180)

	obs, ok := parseDNSMessage(pkt)
	if !ok {
		t.Fatal("应该能解析，却返回 false")
	}
	if obs.Question != "www.example.com" {
		t.Errorf("域名 = %q，期望 www.example.com", obs.Question)
	}
	if len(obs.IPs) != 2 {
		t.Fatalf("地址数 = %d，期望 2", len(obs.IPs))
	}
	if obs.IPs[0] != "93.184.216.34" || obs.IPs[1] != "93.184.216.35" {
		t.Errorf("地址解析错误：%v", obs.IPs)
	}
	// TTL 取所有答案里的最小值，否则一个快过期的记录会被当成长期的
	if obs.TTL != 120 {
		t.Errorf("TTL = %d，期望 120", obs.TTL)
	}
}

func TestParseDNSSkipsQueryAndErrors(t *testing.T) {
	ans := []struct {
		IP  []byte
		TTL uint32
		Typ uint16
	}{{[]byte{1, 2, 3, 4}, 60, 1}}

	// QR=0 是查询包，不该被当成应答
	query := buildDNSResponse("a.com", ans, 0x0100)
	if _, ok := parseDNSMessage(query); ok {
		t.Error("查询包不该被解析成应答")
	}
	// rcode=3（NXDOMAIN）
	nx := buildDNSResponse("a.com", ans, 0x8183)
	if _, ok := parseDNSMessage(nx); ok {
		t.Error("带错误码的应答不该被采纳")
	}
}

func TestParseDNSMalformedNoPanic(t *testing.T) {
	full := buildDNSResponse("www.example.com", []struct {
		IP  []byte
		TTL uint32
		Typ uint16
	}{{[]byte{1, 2, 3, 4}, 60, 1}}, 0x8180)

	// 逐个截断，任何长度都不能 panic
	for i := 0; i < len(full); i++ {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("长度 %d 时 panic: %v", i, r)
				}
			}()
			_, _ = parseDNSMessage(full[:i])
		}()
	}
	// 全是垃圾字节
	if _, ok := parseDNSMessage([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); ok {
		t.Error("垃圾数据不该被解析成功")
	}
}

func TestDNSCompressionLoopNoHang(t *testing.T) {
	// 手工构造一个指向自己的压缩指针，必须被跳转次数限制挡住
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[2:], 0x8180)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[6:], 1)
	b = append(b, 0xC0, 0x0C) // 指回自己
	done := make(chan bool, 1)
	go func() {
		_, _ = parseDNSMessage(b)
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("压缩指针成环导致解析不返回")
	}
}

func TestDomainCacheLookup(t *testing.T) {
	c := NewDomainCache()
	now := int64(1000)
	c.Observe(dnsObservation{Question: "a.example.com", IPs: []string{"1.2.3.4"}, TTL: 300}, now)

	name, extra := c.Lookup("1.2.3.4", now+10)
	if name != "a.example.com" || extra != 0 {
		t.Errorf("Lookup = (%q,%d)，期望 (a.example.com,0)", name, extra)
	}
	// 过期之后必须查不到，否则界面上会一直显示早已失效的域名
	if n, _ := c.Lookup("1.2.3.4", now+301); n != "" {
		t.Errorf("已过期仍返回 %q", n)
	}

	// 同一个 IP 被第二个域名解析到：保留最早的名字，并记一个「还有几个」
	c.Observe(dnsObservation{Question: "b.example.com", IPs: []string{"1.2.3.4"}, TTL: 300}, now)
	name, extra = c.Lookup("1.2.3.4", now+10)
	if name != "a.example.com" {
		t.Errorf("应该保留最早见到的域名，实际 %q", name)
	}
	if extra != 1 {
		t.Errorf("额外域名计数 = %d，期望 1", extra)
	}
}

func TestDomainCacheIPsFor(t *testing.T) {
	c := NewDomainCache()
	now := int64(2000)
	c.Observe(dnsObservation{Question: "cdn.example.com",
		IPs: []string{"5.6.7.8", "1.2.3.4"}, TTL: 300}, now)

	ips := c.IPsFor("cdn.example.com", now+10)
	if len(ips) != 2 || ips[0] != "1.2.3.4" || ips[1] != "5.6.7.8" {
		t.Errorf("IPsFor = %v，期望按字典序 [1.2.3.4 5.6.7.8]", ips)
	}
	// 大小写和结尾点都要能对上
	if got := c.IPsFor("CDN.Example.COM.", now+10); len(got) != 2 {
		t.Errorf("域名归一化失效：%v", got)
	}
	if got := c.IPsFor("cdn.example.com", now+301); len(got) != 0 {
		t.Errorf("过期后不该返回地址：%v", got)
	}
}

func TestValidDomain(t *testing.T) {
	ok := []string{"example.com", "a.b.c.example.co.jp", "x-y.example.com", "_dmarc.example.com"}
	for _, s := range ok {
		if !validDomain(s) {
			t.Errorf("%q 应该合法", s)
		}
	}
	bad := []string{"", "localhost", "example.com; drop", "exa mple.com",
		"example..com", "-bad.com", "bad-.com", "example.com\nip daddr 1.1.1.1"}
	for _, s := range bad {
		if validDomain(s) {
			t.Errorf("%q 应该被判为非法", s)
		}
	}
}

// 域名规则的核心行为：有地址就展开，没地址就跳过。
// 第二条是安全阀，写错了会让用户的目标进程直接断网。
func TestRenderDomainRule(t *testing.T) {
	old := cgroupInodeFn
	cgroupInodeFn = func(string) (uint64, error) { return 4242, nil }
	defer func() { cgroupInodeFn = old }()

	dom := NewDomainCache()
	dom.Seed("example.com", []string{"1.2.3.4", "5.6.7.8", "2001:db8::1"}, 300)

	body, n, out := renderRules([]Rule{{
		Action: "deny", Cgroup: "/system.slice/x.service",
		Kind: "domain", Domain: "example.com", Enabled: true,
	}}, dom)

	// v4 一条、v6 一条：nft 不允许在一个 daddr 集合里混地址族
	if n != 2 {
		t.Fatalf("期望下发 2 条（v4+v6），实际 %d\n%s", n, body)
	}
	if !strings.Contains(body, "ip daddr { 1.2.3.4, 5.6.7.8 }") {
		t.Errorf("缺少 IPv4 集合：\n%s", body)
	}
	if !strings.Contains(body, "ip6 daddr 2001:db8::1") {
		t.Errorf("缺少 IPv6 规则：\n%s", body)
	}
	if out[0].Err != "" {
		t.Errorf("不该有错误：%s", out[0].Err)
	}
	if out[0].IPs != 3 {
		t.Errorf("IPs = %d，期望 3", out[0].IPs)
	}
}

func TestRenderDomainRuleWithoutIPsIsSkipped(t *testing.T) {
	old := cgroupInodeFn
	cgroupInodeFn = func(string) (uint64, error) { return 4242, nil }
	defer func() { cgroupInodeFn = old }()

	dom := NewDomainCache() // 空的，解析不到任何地址
	body, n, out := renderRules([]Rule{{
		Action: "deny", Cgroup: "/system.slice/x.service",
		Kind: "domain", Domain: "notyet.example", Enabled: true,
	}}, dom)

	if n != 0 {
		t.Fatalf("解析不到地址时不该下发任何规则，实际 %d 条\n%s", n, body)
	}
	// 这条断言是整个测试的重点：绝对不能生成「没有 daddr 的 drop」，
	// 那等于把这个进程的所有出向全部掐死。
	if strings.Contains(body, "counter drop") {
		t.Errorf("生成了裸 drop 规则，这会让进程彻底断网：\n%s", body)
	}
	if out[0].Err == "" {
		t.Error("应该标记错误原因，让用户知道规则没生效")
	}
}

func TestRenderDomainRuleNilCache(t *testing.T) {
	old := cgroupInodeFn
	cgroupInodeFn = func(string) (uint64, error) { return 4242, nil }
	defer func() { cgroupInodeFn = old }()

	body, n, out := renderRules([]Rule{{
		Action: "deny", Cgroup: "/x", Kind: "domain", Domain: "a.com", Enabled: true,
	}}, nil)
	if n != 0 || strings.Contains(body, "counter drop") {
		t.Errorf("没有域名缓存时必须跳过，实际 n=%d\n%s", n, body)
	}
	if out[0].Err == "" {
		t.Error("应该说明原因")
	}
}
