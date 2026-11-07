package main

import "testing"

// 对端性质决定了这条连接算不算网络流量。回环判断错了，
// 排行第一名就会是本机两个进程自说自话。
func TestPeerScope(t *testing.T) {
	cases := []struct{ ip, want string }{
		{"127.0.0.1", "loop"},
		{"::1", "loop"},
		{"::ffff:127.0.0.1", "loop"},
		{"192.168.1.10", "lan"},
		{"10.0.0.5", "lan"},
		{"172.16.3.4", "lan"},
		{"fe80::1", "lan"},
		{"fd00::1", "lan"},
		{"47.92.213.69", "wan"},
		{"2a03:2880:f12c:83:face:b00c:25de", "wan"},
		{"", "wan"},
		{"not-an-ip", "wan"},
	}
	for _, c := range cases {
		if got := peerScope(c.ip); got != c.want {
			t.Errorf("peerScope(%q)=%q want %q", c.ip, got, c.want)
		}
	}
}

// 回环连接在宿主机上有两个 socket，字节互为镜像。真机截图里出现过
// pry 累计 89.1 KB / 224.0 KB、nginx 累计 224.0 KB / 89.1 KB 的一对，
// 排行里两行合计完全相同、各占 50.0%——就是两端都记了。
// 这条测试锁住「一对里只能有一端计数」。
func TestLoopPairCountedOnce(t *testing.T) {
	// 客户端 55668 → 服务端 35348
	a := connCountsBytes("loop", 55668, 35348)
	// 服务端 35348 → 客户端 55668
	b := connCountsBytes("loop", 35348, 55668)
	if a == b {
		t.Fatalf("回环连接的两端必须恰好一端计数，got %v/%v", a, b)
	}
	if !a {
		t.Fatalf("应当由本地端口较大的一端记账")
	}

	// 非回环一律计数
	for _, scope := range []string{"lan", "wan"} {
		if !connCountsBytes(scope, 1024, 65535) {
			t.Fatalf("%s 连接必须计数", scope)
		}
	}
}

// 无主 socket 和 TIME_WAIT 不是应用。历史库里必须折进「未归因」，
// 否则「系统 / 无主 socket」会在区间排行里冒充一个独立应用。
func TestAccumulateMapsPseudoToUnattr(t *testing.T) {
	s := newTestStore(t)
	h := NewHub()
	h.AttachStore(s)

	procs := []ProcAgg{
		{Key: "trim-nginx|nginx", Name: "nginx", Service: "trim-nginx", TxRate: 100, RxRate: 200},
		{Key: "系统 / 无主 socket", Name: "系统 / 无主 socket", Pseudo: "unknown", TxRate: 7, RxRate: 9},
		{Key: "已关闭连接", Name: "已关闭连接", Pseudo: "closed", TxRate: 1, RxRate: 1},
	}
	h.accumulate(procs, nil, nil, 0, 0)
	h.FlushNow()

	sum := func(key string) (int64, int64) {
		var tx, rx int64
		err := s.db.QueryRow(
			`SELECT COALESCE(SUM(tx),0), COALESCE(SUM(rx),0) FROM agg WHERE dim='proc' AND key=?`, key,
		).Scan(&tx, &rx)
		if err != nil {
			t.Fatalf("query %q: %v", key, err)
		}
		return tx, rx
	}

	if tx, rx := sum("nginx"); tx != 100 || rx != 200 {
		t.Fatalf("nginx 应保持原名：tx=%d rx=%d", tx, rx)
	}
	if tx, rx := sum(unattrName); tx != 8 || rx != 10 {
		t.Fatalf("两条伪进程应合并成「未归因」：tx=%d rx=%d", tx, rx)
	}
	if tx, _ := sum("系统 / 无主 socket"); tx != 0 {
		t.Fatalf("「系统 / 无主 socket」不该以原名落库，got tx=%d", tx)
	}
}
