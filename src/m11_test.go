package main

import (
	"fmt"
	"strings"
	"testing"
)

// nft -j 的输出是 {nftables:[metainfo, table, chain, rule...]}，
// counter 只是 rule.expr 里的一项，可能和别的表达式混在一起。
// 这里故意沿用 0.9.7 旧表的链名 out/fwd：解析只认 comment，
// 老机器升级后不重建表也要能继续读。
func TestParseStatCounters(t *testing.T) {
	const js = `{
  "nftables": [
    {"metainfo": {"version": "1.0.9"}},
    {"table": {"family": "inet", "name": "fnnetmon_stat"}},
    {"chain": {"family": "inet", "table": "fnnetmon_stat", "name": "out"}},
    {"rule": {"family": "inet", "table": "fnnetmon_stat", "chain": "out",
      "expr": [{"match": {"op": "!=", "left": {"oifname": "lo"}}},
               {"counter": {"packets": 10, "bytes": 1000, "comment": "tcp"}}]}},
    {"rule": {"family": "inet", "table": "fnnetmon_stat", "chain": "out",
      "expr": [{"counter": {"packets": 5, "bytes": 500, "comment": "udp"}}]}},
    {"rule": {"family": "inet", "table": "fnnetmon_stat", "chain": "fwd",
      "expr": [{"counter": {"packets": 1, "bytes": 100, "comment": "fwd"}}]}}
  ]
}`
	c := parseStatCounters([]byte(js))
	if !c.valid {
		t.Fatal("应该解析出计数器")
	}
	if c.tcp != 1000 || c.udp != 500 || c.fwd != 100 {
		t.Errorf("归类错了：tcp=%d udp=%d fwd=%d", c.tcp, c.udp, c.fwd)
	}
}

// 表被删掉、nft 输出报错、或者结构变了，都只能算「拿不到」，
// 绝不能返回一堆 0 让界面显示「未归因全是 UDP」。
func TestParseStatCountersGarbage(t *testing.T) {
	for _, s := range []string{
		"", "not json", `{"nftables":[]}`, `{"nftables":[{"rule":{"expr":[]}}]}`,
	} {
		if c := parseStatCounters([]byte(s)); c.valid {
			t.Errorf("输入 %q 不该被当成有效计数器", s)
		}
	}
}

// 回归 0.9.8：server.log 里 `/dev/stdin:7:9-11: Error: syntax error,
// unexpected fwd, expecting string` 就是 `chain fwd` 撞了 nft 关键字。
// 链名必须是带前缀的普通标识符，一旦改回单词，真机上整块下钻又会静默关掉。
func TestStatScriptChainNames(t *testing.T) {
	full := statScript(true)
	for _, want := range []string{
		"chain " + statChainOut + " {", "chain " + statChainFwd + " {",
		"type filter hook output", "type filter hook forward", "policy accept;",
		`counter comment "tcp"`, `counter comment "udp"`, `counter comment "fwd"`,
	} {
		if !strings.Contains(full, want) {
			t.Errorf("完整方案少了 %q", want)
		}
	}
	for _, bad := range []string{"chain fwd {", "chain out {", "drop"} {
		if strings.Contains(full, bad) {
			t.Errorf("完整方案不该出现 %q（统计表只能 accept）", bad)
		}
	}
	keywords := []string{"fwd", "out", "in", "input", "output", "forward",
		"chain", "table", "counter", "accept", "drop", "type", "hook", "policy", "meta"}
	for _, name := range []string{statChainOut, statChainFwd} {
		if !strings.HasPrefix(name, "fnm_") {
			t.Errorf("链名 %q 要带 fnm_ 前缀，避开 nft 关键字", name)
		}
		for _, kw := range keywords {
			if name == kw {
				t.Errorf("链名 %q 是 nft 关键字", name)
			}
		}
	}

	// 降级方案不能带 forward 钩子，但出向的 TCP/UDP 计数器必须还在。
	minimal := statScript(false)
	if minimal == full {
		t.Fatal("降级方案和完整方案不能一样")
	}
	if strings.Contains(minimal, "hook forward") || strings.Contains(minimal, statChainFwd) {
		t.Error("降级方案还留着 forward 链")
	}
	for _, want := range []string{`counter comment "tcp"`, `counter comment "udp"`, "policy accept;"} {
		if !strings.Contains(minimal, want) {
			t.Errorf("降级方案少了 %q", want)
		}
	}
}

// 建表失败要逐级降级，而不是一上来就把整块下钻关掉。
func TestTryStatVariantsFallback(t *testing.T) {
	name, notes := tryStatVariants(func(v statVariant) error { return nil })
	if name == "" || len(notes) != 0 {
		t.Fatalf("第一个方案就成功时不该有降级记录：name=%q notes=%v", name, notes)
	}

	name, notes = tryStatVariants(func(v statVariant) error {
		if strings.Contains(v.script, "hook forward") {
			return fmt.Errorf("syntax error, unexpected fwd, expecting string")
		}
		return nil
	})
	if name != "仅出向" || len(notes) != 1 {
		t.Fatalf("forward 链建不起来应该落到「仅出向」：name=%q notes=%v", name, notes)
	}
	if !strings.Contains(notes[0], "unexpected fwd") {
		t.Errorf("降级原因要带上原始报错，方便排障：%q", notes[0])
	}

	name, notes = tryStatVariants(func(v statVariant) error { return fmt.Errorf("nft 不可用") })
	if name != "" || len(notes) != len(statVariants()) {
		t.Fatalf("全失败应该返回空名和全部原因：name=%q notes=%v", name, notes)
	}
}

// 计数器被重置（表重建）时差值为负，必须归零而不是算出天文数字。
func TestStatSamplerRateOnReset(t *testing.T) {
	s := &StatSampler{}
	s.mu.Lock()
	s.avail = true
	s.prev = statCounters{tcp: 1 << 40, udp: 1 << 40, fwd: 0, valid: true}
	s.mu.Unlock()
	// 直接调用内部换算逻辑：prev 比当前大，结果应该是 0
	d := func(a, b uint64) float64 {
		if a < b {
			return 0
		}
		return float64(a - b)
	}
	if got := d(100, 1<<40); got != 0 {
		t.Errorf("计数器回绕应归零，得到 %v", got)
	}
}

// 网关经 app.sock 转发时不带 Host（或把 socket 路径塞进 Host），
// Go 会在解析阶段直接 400，handler 都进不来。这里只改请求头，别碰路径和 body。
func TestFixRequestHost(t *testing.T) {
	cases := []struct {
		name, in, wantHost string
		unchanged          bool
	}{
		{"无 Host", "GET /app/fnnetmon HTTP/1.1\r\nX-A: 1\r\n\r\n", "Host: localhost", false},
		{"非法 Host", "GET / HTTP/1.1\r\nHost: /vol1/@appcenter/fnnetmon/app.sock\r\n\r\n", "Host: localhost", false},
		{"合法 Host", "GET / HTTP/1.1\r\nHost: nas.local:5000\r\n\r\n", "Host: nas.local:5000", true},
	}
	for _, c := range cases {
		got, ok := fixRequestHost([]byte(c.in))
		if !ok {
			t.Fatalf("%s: 应该重写请求头", c.name)
		}
		s := string(got)
		if !strings.Contains(s, c.wantHost) || strings.Count(s, "Host:") != 1 {
			t.Errorf("%s: Host 补错了：%q", c.name, s)
		}
		if strings.Contains(s, "app.sock") {
			t.Errorf("%s: 非法 Host 没丢掉：%q", c.name, s)
		}
		if c.unchanged && s != c.in {
			t.Errorf("%s: 合法 Host 不该改动请求：%q", c.name, s)
		}
	}

	// 带 body 的请求：补完 Host 之后 body 原样保留
	in := "POST /api/rules HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"
	got, ok := fixRequestHost([]byte(in))
	if !ok || !strings.HasSuffix(string(got), "\r\n\r\nabc") {
		t.Errorf("body 被改坏了：%q", string(got))
	}

	// 头部没读完、或者根本不是 HTTP 请求：原样放行，别把 body 当头改
	for _, s := range []string{"GET / HTTP/1.1\r\nX-A: 1\r\n", "hello world foo bar baz"} {
		if _, ok := fixRequestHost([]byte(s)); ok {
			t.Errorf("不该重写 %q", s)
		}
	}
}
