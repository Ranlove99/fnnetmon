package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const version = "0.9.9"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: fnnetmon <diag|serve|snapshot|svc|geo|firewall|selfcheck|version>\n")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "diag":
		runDiag(os.Args[2:])
	case "snapshot":
		runSnapshot(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "svc":
		runSvc(os.Args[2:])
	case "firewall":
		runFirewall(os.Args[2:])
	case "selfcheck":
		runSelfCheck(os.Args[2:])
	case "geo":
		runGeo(os.Args[2:])
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

// runSelfCheck 输出一次运行状态快照。SSH 里不用起服务就能看，
// 主要用来对比「昨天和今天的内存差多少」。
func runSelfCheck(args []string) {
	fs := flag.NewFlagSet("selfcheck", flag.ExitOnError)
	varDir := fs.String("var", "", "data dir（留空自动猜）")
	asJSON := fs.Bool("json", false, "输出 JSON")
	fs.Parse(args)

	dir := resolveVarDir(*varDir)
	var store *Store
	if st, err := OpenStore(filepath.Join(dir, "db")); err == nil {
		store = st
		defer store.Close()
	}
	fw := &Firewall{}
	fw.Probe()

	sc := BuildSelfCheck(nil, store, fw, nil)
	if *asJSON {
		b, _ := json.MarshalIndent(sc, "", "  ")
		fmt.Println(string(b))
		return
	}
	fmt.Print(sc.Text())
}

// runFirewall 是拦截功能的逃生口。规则写错把自己锁在门外时，
// SSH 里执行 `fnnetmon firewall off` 就能立刻恢复，不依赖服务是否还在跑。
func runFirewall(args []string) {
	fs := flag.NewFlagSet("firewall", flag.ExitOnError)
	varDir := fs.String("var", "/var/apps/fnnetmon/var", "data dir")
	fs.Parse(args)

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fnnetmon firewall <off|status>")
		os.Exit(1)
	}
	fw := &Firewall{}
	switch fs.Args()[0] {
	case "off":
		err := fw.Clear()
		// 统计表也一起清掉：它不拦流量，但留着没人认领的表同样不干净
		(&StatSampler{}).Clear()
		_ = fwStateSave(filepath.Join(*varDir, "firewall.json"), false)
		if err != nil {
			// 表本来就不存在也会报错，这里不当失败。别把 nft 的原始
			// "Error: ..." 打进 server.log：用户看到会以为服务坏了，
			// 其实只是停止时的一次例行清理（0.9.8 在 x86 日志里踩过）。
			fmt.Println("table inet fnnetmon 不存在或已清除，无需处理")
		} else {
			fmt.Println("已清除 table inet fnnetmon，出向拦截全部解除")
			// 提示只在真的清掉表时给：stop 脚本每次都会调这条命令，
			// 表本来就不存在还喊「请停止服务」纯属吓人。
			fmt.Println("如服务仍在运行，请一并停止，避免规则被重新下发：")
			fmt.Println("      systemctl stop 或 kill $(cat " + filepath.Join(*varDir, "fnnetmon.pid") + ")")
		}
	case "status":
		fw.Probe()
		st := fw.Status()
		fmt.Printf("可用: %v\n原因: %s\n版本: %s\n", st.Available, st.Reason, st.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown firewall action: %s\n", fs.Args()[0])
		os.Exit(1)
	}
}

func runDiag(args []string) {
	fs := flag.NewFlagSet("diag", flag.ExitOnError)
	out := fs.String("out", "", "write report to file")
	fs.Parse(args)

	rep := Collect()
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out != "" {
		if err := os.MkdirAll(filepath.Dir(*out), 0o755); err == nil {
			_ = os.WriteFile(*out, b, 0o644)
		}
	}
	fmt.Println(string(b))
}

// runSnapshot 打印一次采集结果，方便 SSH 下排查。
func runSnapshot(args []string) {
	fs := flag.NewFlagSet("snapshot", flag.ExitOnError)
	wait := fs.Duration("wait", 3*time.Second, "采集时长")
	fs.Parse(args)

	h := NewHub()
	h.Start()
	time.Sleep(*wait)
	snap := h.Snapshot()
	b, _ := json.MarshalIndent(snap, "", "  ")
	fmt.Println(string(b))
}

type cache struct {
	mu   sync.Mutex
	rep  *Report
	when time.Time
}

func (c *cache) get(ttl time.Duration) *Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rep != nil && time.Since(c.when) < ttl {
		return c.rep
	}
	r := Collect()
	c.rep, c.when = r, time.Now()
	return r
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "0.0.0.0:18089", "tcp listen address")
	sock := fs.String("sock", "", "unix socket path (for fnOS gateway)")
	varDir := fs.String("var", "/tmp/fnnetmon", "data dir")
	noTCP := fs.Bool("no-tcp", false, "disable tcp listener")
	fs.Parse(args)

	_ = os.MkdirAll(*varDir, 0o755)

	// 依赖一次性装配好。下面五个 init 的顺序是有依赖的：
	// store 先于 peers（外联记录要落库）、dom 先于 fw（域名规则要解析地址）、
	// geo 先于 geoJob（热加载要换 reader）。
	s := &server{
		varDir: *varDir,
		hub:    NewHub(),
		dom:    NewDomainCache(),
		fw:     NewFirewall(),
		alerts: NewAlertEngine(filepath.Join(*varDir, "alerts.json")),
		stat:   NewStatSampler(),
		dc:     &cache{},
	}
	s.fwPath = filepath.Join(*varDir, "firewall.json")

	s.openHistory()
	s.startAttribution()
	s.restoreFirewall()
	s.watchSignals()
	s.startSamplers()

	handler := s.routes()

	if *sock != "" {
		_ = os.Remove(*sock)
		_ = os.MkdirAll(filepath.Dir(*sock), 0o755)
		ln, err := net.Listen("unix", *sock)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unix listen failed: %v\n", err)
		} else {
			_ = os.Chmod(*sock, 0o666)
			go func() {
				srv := &http.Server{Handler: handler}
				// 兼容层只在连接的第一次 Read 补 Host，所以禁掉 keep-alive：
				// 一个连接一个请求，网关重连即可，不会出现第二个请求又缺 Host。
				srv.SetKeepAlivesEnabled(false)
				fmt.Fprintf(os.Stderr, "[fnnetmon] unix socket on %s\n", *sock)
				_ = srv.Serve(hostFixListener{Listener: ln})
			}()
		}
	}

	if !*noTCP {
		srv := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
		fmt.Fprintf(os.Stderr, "[fnnetmon] tcp on %s\n", *addr)
		if err := srv.ListenAndServe(); err != nil {
			fmt.Fprintf(os.Stderr, "tcp listen failed: %v\n", err)
		}
	} else {
		select {}
	}
}

// openHistory 打开历史库。失败不致命：实时监控照常工作，只是没有历史和排行。
func (s *server) openHistory() {
	st, err := OpenStore(filepath.Join(s.varDir, "db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fnnetmon] history disabled: %v\n", err)
		return
	}
	s.store = st
	s.hub.AttachStore(st)
	go maintain(st)
	fmt.Fprintf(os.Stderr, "[fnnetmon] history at %s\n", filepath.Join(s.varDir, "db"))
}

// startAttribution 装配外联追踪、DNS 抓包、地理库，并把它们挂到 hub 上。
//
// 这三件事都是「锦上添花」型：任何一件失败都不影响主采集循环，
// 界面会显示具体原因，而不是整个服务起不来。
func (s *server) startAttribution() {
	// 外联追踪：即使没有历史库也能纯内存工作
	s.peers = NewPeerTracker(s.store)
	s.hub.AttachPeer(s.peers)

	// 服务名：appcenter-cli 是外部进程，单独一条 goroutine 每 5 分钟问一次，
	// 不能塞进 1 秒的采集 tick 里（会顶爆「单 tick ≤ 500ms」的预算）。
	s.hub.svc.StartAppCenterWatch(5 * time.Minute)

	// 域名归因：AF_PACKET 抓 DNS 应答。失败不致命，界面会显示原因。
	s.sniffer = startDNSSniffer(s.dom)
	fmt.Fprintf(os.Stderr, "[fnnetmon] dns attribution: running=%v %s\n",
		s.dom.Stats().Running, s.dom.Stats().Error)

	// 地理/ASN：内置库随包发布，数据目录里的库优先（用户想换新版本不用重打包）
	s.geo = OpenGeo(geoDirs(s.varDir)...)
	if s.geo.Available() {
		st := s.geo.Status()
		fmt.Fprintf(os.Stderr, "[fnnetmon] geoip: %v（%s，构建 %s）\n", st.Files, st.Source, st.Build)
	}
	// 省市数据按需安装：装完热加载，不重启进程
	s.geoJob = NewGeoJob(s.geo, filepath.Join(s.varDir, "geo"))

	s.peers.AttachEnrich(s.dom, s.geo)
	s.hub.AttachEnrich(s.dom, s.geo)
	s.peers.OnNew(func(p Peer) {
		// 只在日志里留痕。NAS 上没有桌面通知，日志 + 界面角标是仅有的两个出口。
		name := p.IP
		if n, _ := s.dom.Lookup(p.IP, time.Now().Unix()); n != "" {
			name = n + " (" + p.IP + ")"
		}
		fmt.Fprintf(os.Stderr, "[fnnetmon] new peer: %s → %s\n", p.Proc, name)
	})
}

// restoreFirewall 按上次的状态恢复拦截，并清理非正常退出留下的残留表。
//
// 主动拦截默认关闭，只有用户显式打开过才会下发规则。
func (s *server) restoreFirewall() {
	s.fw.SetDomainCache(s.dom)
	if fwStateLoad(s.fwPath) && s.fw.Status().Available && s.store != nil {
		if rules, err := s.store.ListRules(); err == nil {
			if err := s.fw.SetEnforce(true, rules); err != nil {
				fmt.Fprintf(os.Stderr, "[fnnetmon] restore firewall failed: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "[fnnetmon] firewall restored with %d rules\n", s.fw.Status().Applied)
			}
		}
	} else {
		_ = s.fw.Clear() // 上次可能是非正常退出，残留的表要清掉
	}
	fmt.Fprintf(os.Stderr, "[fnnetmon] firewall available=%v %s\n",
		s.fw.Status().Available, s.fw.Status().Reason)

	if s.store != nil {
		go refreshDomainRules(s.store, s.fw, s.dom)
	}
}

// watchSignals 在收到 TERM/INT 时把该落的都落掉。
//
// 顺序有讲究：先落数据（丢了就没了），再清内核表（不清会让用户既连不上网
// 又找不到地方关），最后才关库。
func (s *server) watchSignals() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc
		fmt.Fprintf(os.Stderr, "[fnnetmon] shutting down, flushing history\n")
		s.hub.FlushNow()
		if s.peers != nil {
			s.peers.Flush()
		}
		s.sniffer.Stop()
		// 服务不跑了，拦截规则就不该继续生效 —— 否则用户既连不上网也找不到地方关。
		_ = s.fw.Clear()
		s.geo.Close()
		if s.store != nil {
			_ = s.store.Rollup()
			_ = s.store.Close()
		}
		os.Exit(0)
	}()
}

// startSamplers 起后台循环：采集、未归因统计、告警评估。
func (s *server) startSamplers() {
	s.hub.Start()

	// 未归因下钻：一张只统计、不拦截的 nft 表，按协议和转发分开计数。
	// 挂独立 goroutine，nft 不可用（或权限不够）时整块静默降级，
	// 界面只显示「未归因」总数，不显示细分——绝不影响主采集循环。
	s.hub.AttachStat(s.stat)
	go s.stat.Run(5*time.Second, func(msg string) {
		fmt.Fprintf(os.Stderr, "[fnnetmon] unattr breakdown off: %s\n", firstLine(msg))
	})

	// 流量告警：30 秒评估一轮，配置存 alerts.json（和 SQLite 解耦）。
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			s.alerts.Evaluate(s.hub.Snapshot(), 30)
		}
	}()
}

// maintain 负责滚动汇总和数据保留期清理。
// 4GB 内存设备上，1m 数据 7 天约几十万行，5 分钟一次的增量 rollup 完全扛得住。
func maintain(st *Store) {
	// 启动时补一次，处理上次非正常退出遗留的缺口
	time.Sleep(20 * time.Second)
	_ = st.Rollup()
	_ = st.Purge()

	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	n := 0
	for range t.C {
		if err := st.Rollup(); err != nil {
			fmt.Fprintf(os.Stderr, "[fnnetmon] rollup failed: %v\n", err)
		}
		n++
		if n%12 == 0 { // 约每小时清理一次
			if err := st.Purge(); err != nil {
				fmt.Fprintf(os.Stderr, "[fnnetmon] purge failed: %v\n", err)
			}
		}
	}
}

// refreshDomainRules 定期重新解析域名规则里的域名。
//
// CDN 域名背后是一组会变的 IP，一次性解析完就不管的话，
// 过几天规则就只封住了一批已经没人用的地址。每 5 分钟对一次，
// 只有地址集合真的变了才重新下发 —— 否则每 5 分钟重建一次规则表，
// 中间的瞬间是「全放行」，没必要制造这种窗口。
func refreshDomainRules(store *Store, fw *Firewall, dom *DomainCache) {
	time.Sleep(45 * time.Second) // 启动时先让抓包跑一会儿
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		rules, err := store.ListRules()
		if err != nil {
			continue
		}
		var targets []string
		for _, r := range rules {
			if r.Enabled && r.Kind == "domain" && r.Domain != "" {
				targets = append(targets, r.Domain)
			}
		}
		if len(targets) == 0 {
			continue
		}
		changed := false
		now := time.Now().Unix()
		for _, d := range targets {
			before := dom.IPsFor(d, now)
			ips, err := dom.Resolve(d)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[fnnetmon] refresh %s: %v\n", d, firstLine(err.Error()))
				continue
			}
			sorted := append([]string{}, ips...)
			sort.Strings(sorted)
			if !equalStrings(before, sorted) {
				changed = true
			}
		}
		if changed {
			fw.Reload(rules)
			fmt.Fprintf(os.Stderr, "[fnnetmon] domain rules refreshed\n")
		}
	}
}

// fillRuleIPs 给域名规则补上「当前已知地址数」，只用于展示。
func fillRuleIPs(rules []Rule, dom *DomainCache) {
	if dom == nil {
		return
	}
	now := time.Now().Unix()
	for i := range rules {
		if rules[i].Kind == "domain" && rules[i].Domain != "" {
			rules[i].IPs = len(dom.IPsFor(rules[i].Domain, now))
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func gatewayInfo(r *http.Request) map[string]string {
	m := map[string]string{}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-trim-") || lk == "x-forwarded-for" || lk == "x-real-ip" {
			m[k] = strings.Join(v, ",")
		}
	}
	m["_remote_addr"] = r.RemoteAddr
	m["_path"] = r.URL.Path
	return m
}

func jsonReply(w http.ResponseWriter, v any, code int) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = w.Write(b)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	return dec.Decode(v)
}

// beginCSV 设置下载头并写出 UTF-8 BOM。
// BOM 不是可选项：Excel 不看 Content-Type，没有 BOM 就把 UTF-8 当 GBK 解，中文列名全变乱码。
func beginCSV(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("\xef\xbb\xbf"))
}

// reloadRules 规则变动后重新下发。没开启拦截时只更新内存状态，不碰内核。
func reloadRules(store *Store, fw *Firewall) {
	if store == nil || fw == nil {
		return
	}
	rules, err := store.ListRules()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fnnetmon] load rules failed: %v\n", err)
		return
	}
	fw.Reload(rules)
}

// 拦截开关单独存一个文件，不放进 SQLite —— 历史库坏掉的时候，
// 「关掉拦截」这件事必须还能正常工作。
func fwStateLoad(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var s struct {
		Enforce bool `json:"enforce"`
	}
	if json.Unmarshal(b, &s) != nil {
		return false
	}
	return s.Enforce
}

func fwStateSave(path string, on bool) error {
	b, _ := json.Marshal(map[string]bool{"enforce": on})
	return os.WriteFile(path, b, 0o644)
}
