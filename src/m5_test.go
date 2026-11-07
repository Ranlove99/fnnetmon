package main

import (
	"strings"
	"testing"
)

// 白名单是安全底线：只要它在，规则写错也不会把内网和 SSH 拦死。
func TestRenderRulesAlwaysHasWhitelist(t *testing.T) {
	body, n, _ := renderRules(nil, nil)
	if n != 0 {
		t.Fatalf("空规则集不该下发任何规则，得到 %d", n)
	}
	must := []string{
		`oifname "lo" accept`,
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fe80::/10",
		"fc00::/7",
		"ff00::/8",
	}
	for _, m := range must {
		if !strings.Contains(body, m) {
			t.Errorf("白名单缺少 %q，这会让内网或回环被误拦", m)
		}
	}
}

// cgroup 路径不存在时必须跳过这条规则，而不是下发一条匹配不到任何东西的死规则。
func TestRenderRulesSkipsMissingCgroup(t *testing.T) {
	rules := []Rule{{
		Action: "deny", Proc: "qbittorrent", Cgroup: "/system.slice/definitely-not-exist.service",
		IP: "1.2.3.4", Enabled: true,
	}}
	_, n, out := renderRules(rules, nil)
	if n != 0 {
		t.Fatalf("cgroup 不存在时不应下发，得到 %d", n)
	}
	if len(out) != 1 || out[0].Err == "" {
		t.Fatalf("应该标记该规则的错误原因，得到 %+v", out)
	}
}

func TestRenderRulesSkipsDisabled(t *testing.T) {
	_, n, _ := renderRules([]Rule{{Action: "deny", Cgroup: "/x", Enabled: false}}, nil)
	if n != 0 {
		t.Fatalf("未启用的规则不应下发，得到 %d", n)
	}
}

// 完整链体的语法检查。测试机没有 /sys/fs/cgroup，这里替换掉 inode 解析。
func TestRenderRulesFullScript(t *testing.T) {
	old := cgroupInodeFn
	cgroupInodeFn = func(string) (uint64, error) { return 4242, nil }
	defer func() { cgroupInodeFn = old }()

	body, n, _ := renderRules([]Rule{
		{Action: "deny", Cgroup: "/system.slice/a.service", IP: "1.2.3.4", Enabled: true},
		{Action: "deny", Cgroup: "/system.slice/b.service", IP: "2001:db8::1", Port: 443, Enabled: true},
		{Action: "allow", Cgroup: "/system.slice/c.service", Enabled: true},
	}, nil)
	if n != 3 {
		t.Fatalf("期望 3 条下发，得到 %d", n)
	}
	t.Logf("生成的链体：\n%s", body)

	for _, line := range strings.Split(body, "\n") {
		// 裸的 th dport 会让 nft 拒绝整个脚本（transport header 需要 l4 协议前置）
		if strings.Contains(line, "th dport") && !strings.Contains(line, "meta l4proto") {
			t.Errorf("端口匹配缺少 l4 协议前置：%q", line)
		}
	}
}

func TestRuleExpr(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want []string
		not  []string
	}{
		{
			name: "只按进程拦",
			rule: Rule{Action: "deny"},
			want: []string{"meta cgroup 42", "counter drop"},
			not:  []string{"daddr", "dport"},
		},
		{
			name: "进程 + IPv4 + 端口",
			rule: Rule{Action: "deny", IP: "1.2.3.4", Port: 443},
			want: []string{"meta cgroup 42", "ip daddr 1.2.3.4", "th dport 443", "counter drop"},
		},
		{
			name: "IPv6 必须用 ip6 daddr",
			rule: Rule{Action: "deny", IP: "2001:db8::1"},
			want: []string{"ip6 daddr 2001:db8::1"},
			not:  []string{"ip daddr"},
		},
		{
			name: "allow 生成 accept",
			rule: Rule{Action: "allow", IP: "8.8.8.8"},
			want: []string{"accept"},
			not:  []string{"drop"},
		},
	}
	for _, c := range cases {
		expr, err := ruleExpr(c.rule, 42)
		if err != nil {
			t.Fatalf("%s: 意外错误 %v", c.name, err)
		}
		for _, w := range c.want {
			if !strings.Contains(expr, w) {
				t.Errorf("%s: 期望包含 %q，实际 %q", c.name, w, expr)
			}
		}
		for _, n := range c.not {
			if strings.Contains(expr, n) {
				t.Errorf("%s: 不该包含 %q，实际 %q", c.name, n, expr)
			}
		}
	}
}

// 非法地址必须在生成 nft 语法之前就被挡住，否则会把整张表下发失败。
func TestValidCIDR(t *testing.T) {
	ok := []string{"1.2.3.4", "10.0.0.0/8", "2001:db8::1", "::1", "fe80::/10"}
	for _, s := range ok {
		if err := validCIDR(s); err != nil {
			t.Errorf("%q 应该合法，却报错 %v", s, err)
		}
	}
	bad := []string{"1.2.3.4; rm -rf /", "1.2.3.4 accept", "abc", "1.2.3.4\ndrop", "1.2.3.4,5.6.7.8"}
	for _, s := range bad {
		if err := validCIDR(s); err == nil {
			t.Errorf("%q 应该被拒绝", s)
		}
	}
}

// ---- 外联追踪 ----

func TestPeerObserveAggregatesByIP(t *testing.T) {
	tr := NewPeerTracker(nil)
	tr.Observe(obs("chrome", "", "/system.slice/chrome.service", "1.2.3.4", 443, "tcp", true, 100, 200))
	// 同一进程连同一 IP 的不同端口，应该合并成一条
	tr.Observe(obs("chrome", "", "", "1.2.3.4", 8443, "tcp", true, 300, 500))
	// 后续采样不算新连接
	tr.Observe(obs("chrome", "", "", "1.2.3.4", 443, "tcp", false, 900, 1200))

	list := tr.List(false, false, "", 10)
	if len(list) != 1 {
		t.Fatalf("同一 (proc,ip) 应该只有一条，得到 %d", len(list))
	}
	p := list[0]
	if p.Hits != 2 {
		t.Errorf("hits 应等于新连接次数 2，得到 %d", p.Hits)
	}
	if p.Tx != 900 || p.Rx != 1200 {
		t.Errorf("流量应取最新累计值 900/1200，得到 %d/%d", p.Tx, p.Rx)
	}
	if p.Cgroup != "/system.slice/chrome.service" {
		t.Errorf("cgroup 不该被空值覆盖，得到 %q", p.Cgroup)
	}
}

func TestPeerSkipsLoopback(t *testing.T) {
	tr := NewPeerTracker(nil)
	tr.Observe(obs("x", "", "", "127.0.0.1", 80, "tcp", true, 0, 0))
	tr.Observe(obs("x", "", "", "::1", 80, "tcp", true, 0, 0))
	if n := tr.Count(); n != 0 {
		t.Fatalf("回环不该被记录，得到 %d 条", n)
	}
}

func TestPeerPrivateFilter(t *testing.T) {
	tr := NewPeerTracker(nil)
	tr.Observe(obs("nas", "", "", "192.168.1.10", 445, "tcp", true, 0, 0))
	tr.Observe(obs("nas", "", "", "1.2.3.4", 443, "tcp", true, 0, 0))

	if n := len(tr.List(false, false, "", 10)); n != 1 {
		t.Fatalf("默认应过滤内网，期望 1 条，得到 %d", n)
	}
	if n := len(tr.List(true, false, "", 10)); n != 2 {
		t.Fatalf("勾选内网后应有 2 条，得到 %d", n)
	}
	if n := tr.Pending(); n != 1 {
		t.Fatalf("待裁决只算公网，期望 1，得到 %d", n)
	}
}

func TestPeerVerdictAndPending(t *testing.T) {
	tr := NewPeerTracker(nil)
	tr.Observe(obs("curl", "", "/system.slice/x.service", "1.1.1.1", 443, "tcp", true, 0, 0))
	if tr.Pending() != 1 {
		t.Fatal("新对端应计入待裁决")
	}
	if err := tr.SetVerdict("curl", "1.1.1.1", "deny"); err != nil {
		t.Fatal(err)
	}
	if tr.Pending() != 0 {
		t.Fatal("已裁决的不该再计入待裁决")
	}
	if n := len(tr.List(false, true, "", 10)); n != 0 {
		t.Fatalf("只看未裁决时应为空，得到 %d", n)
	}
	if p := tr.Get("curl", "1.1.1.1"); p == nil || p.Verdict != "deny" {
		t.Fatalf("Get 应返回带裁决的记录，得到 %+v", p)
	}
}

func TestPeerSearch(t *testing.T) {
	tr := NewPeerTracker(nil)
	tr.Observe(obs("qbittorrent", "", "/system.slice/qb.service", "203.0.113.9", 6881, "tcp", true, 0, 0))
	tr.Observe(obs("curl", "", "/system.slice/curl.service", "1.1.1.1", 443, "tcp", true, 0, 0))

	if n := len(tr.List(false, false, "QBIT", 10)); n != 1 {
		t.Fatalf("搜索应不区分大小写，得到 %d", n)
	}
	if n := len(tr.List(false, false, "203.0", 10)); n != 1 {
		t.Fatalf("搜索应匹配 IP 前缀，得到 %d", n)
	}
	if n := len(tr.List(false, false, "不存在的关键词", 10)); n != 0 {
		t.Fatalf("无匹配时应为空，得到 %d", n)
	}
}

// 撤销裁决时只能清掉自动生成的那条，用户手动加的规则必须留着。
func TestDeleteAutoRulesOnlyRemovesAuto(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	auto, err := s.AddRule(Rule{Action: "deny", Proc: "curl", Cgroup: "/x", IP: "1.1.1.1", Enabled: true, Note: autoRuleNote})
	if err != nil {
		t.Fatal(err)
	}
	manual, err := s.AddRule(Rule{Action: "deny", Proc: "curl", Cgroup: "/x", IP: "1.1.1.1", Enabled: true, Note: "手动加的"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.AddRule(Rule{Action: "deny", Proc: "curl", Cgroup: "/x", IP: "9.9.9.9", Enabled: true, Note: autoRuleNote})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteAutoRules("curl", "1.1.1.1", ""); err != nil {
		t.Fatal(err)
	}
	rules, err := s.ListRules()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[int64]bool{}
	for _, r := range rules {
		ids[r.ID] = true
	}
	if ids[auto] {
		t.Errorf("自动规则 %d 应被删除", auto)
	}
	if !ids[manual] {
		t.Errorf("手动规则 %d 不该被删", manual)
	}
	if !ids[other] {
		t.Errorf("其他对端的自动规则 %d 不该被删", other)
	}
}

// 规则开关与删除
func TestRuleCRUD(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	id, err := s.AddRule(Rule{Action: "deny", Proc: "p", Cgroup: "/c", IP: "1.2.3.4", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetRuleEnabled(id, false); err != nil {
		t.Fatal(err)
	}
	rules, _ := s.ListRules()
	if len(rules) != 1 || rules[0].Enabled {
		t.Fatalf("应只有 1 条且已停用，得到 %+v", rules)
	}
	if err := s.DeleteRule(id); err != nil {
		t.Fatal(err)
	}
	rules, _ = s.ListRules()
	if len(rules) != 0 {
		t.Fatalf("删除后应为空，得到 %d", len(rules))
	}
}

// 对端落库再读回来，verdict 不能被采集循环覆盖
func TestPeerPersistKeepsVerdict(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	tr := NewPeerTracker(s)
	tr.Observe(obs("curl", "", "/system.slice/c.service", "1.1.1.1", 443, "tcp", true, 10, 20))
	tr.Flush()
	if err := tr.SetVerdict("curl", "1.1.1.1", "deny"); err != nil {
		t.Fatal(err)
	}

	// 模拟重启：重新 load
	tr2 := NewPeerTracker(s)
	p := tr2.Get("curl", "1.1.1.1")
	if p == nil {
		t.Fatal("重启后应能读回对端记录")
	}
	if p.Verdict != "deny" {
		t.Errorf("verdict 应持久化为 deny，得到 %q", p.Verdict)
	}

	// 再次观测并落盘，verdict 不能被冲掉
	tr2.Observe(obs("curl", "", "/system.slice/c.service", "1.1.1.1", 443, "tcp", false, 99, 99))
	tr2.Flush()
	tr3 := NewPeerTracker(s)
	if p := tr3.Get("curl", "1.1.1.1"); p == nil || p.Verdict != "deny" {
		t.Errorf("采集循环不该覆盖用户裁决，得到 %+v", p)
	}
}

// obs 让测试可以用位置参数构造 peerObs，保持原来的写法不用大改。
func obs(proc, cont, cg, ip string, port int, proto string, fresh bool, tx, rx uint64) peerObs {
	return peerObs{Proc: proc, Cont: cont, Cgroup: cg, IP: ip, Port: port, Proto: proto, Fresh: fresh, Tx: tx, Rx: rx}
}
