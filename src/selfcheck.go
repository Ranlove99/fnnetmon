package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// 这些是给 4GB 内存设备定的预算值。超了不一定是 bug，但必须有解释——
// 长期跑下来「慢慢变胖」才是最难查的那类问题。
const (
	budgetRSSMB     = 60.0
	budgetGoroutine = 100
	budgetFDs       = 256
	budgetDBMB      = 100.0
	budgetTickMs    = 500.0 // 单次采集超过 1 秒就会丢采样
)

type SelfCheck struct {
	Version string          `json:"version"`
	Uptime  int64           `json:"uptime_sec"`
	TS      string          `json:"ts"`
	Runtime SelfRuntime     `json:"runtime"`
	Collect SelfCollect     `json:"collect"`
	Storage SelfStorage     `json:"storage"`
	Checks  []SelfCheckItem `json:"checks"`
	Verdict string          `json:"verdict"` // ok | warn | bad
}

type SelfRuntime struct {
	RSSMB     float64 `json:"rss_mb"`
	GeoMB     float64 `json:"geo_mb"` // 地理库 mmap 占用的驻留部分，从 RSS 预算里扣除
	HeapMB    float64 `json:"heap_mb"`
	SysMB     float64 `json:"sys_mb"`
	Goroutine int     `json:"goroutines"`
	FDs       int     `json:"fds"`
	GCCount   uint32  `json:"gc_count"`
	NumCPU    int     `json:"num_cpu"`
}

type SelfCollect struct {
	Ticks   int64   `json:"ticks"`
	LastMs  float64 `json:"last_ms"`
	MaxMs   float64 `json:"max_ms"`
	AvgMs   float64 `json:"avg_ms"`
	IdleSec int64   `json:"idle_sec"` // 距最近一次 tick 过了多久
	Procs   int     `json:"procs_tracked"`
	Conts   int     `json:"conts_tracked"`
	Conns   int     `json:"conns"`
	Peers   int     `json:"peers"`
	Pending int     `json:"peers_pending"`
}

type SelfStorage struct {
	Path      string  `json:"path"`
	DBSizeMB  float64 `json:"db_mb"`
	WALSizeMB float64 `json:"wal_mb"`
	Rows1m    int64   `json:"rows_1m"`
	Rows1h    int64   `json:"rows_1h"`
	Rows1d    int64   `json:"rows_1d"`
	Rules     int     `json:"rules"`
	OK        bool    `json:"ok"`
}

type SelfCheckItem struct {
	Name  string `json:"name"`
	Level string `json:"level"` // ok | warn | bad
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

// BuildSelfCheck 汇总运行状态。所有数据源都允许失败：
// 自检工具本身不应该因为某个子系统坏了就整个跑不出来。
func BuildSelfCheck(h *Hub, store *Store, fw *Firewall, peers *PeerTracker) *SelfCheck {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	rss := readRSSMB()
	if rss == 0 {
		// 非 Linux 环境没有 /proc，用运行时统计兜底
		rss = float64(ms.Sys) / (1 << 20)
	}
	geoMB := readGeoRSSMB()

	sc := &SelfCheck{
		Version: version,
		TS:      time.Now().Format("2006-01-02 15:04:05"),
		Runtime: SelfRuntime{
			RSSMB:     round1(rss),
			GeoMB:     round1(geoMB),
			HeapMB:    round1(float64(ms.HeapAlloc) / (1 << 20)),
			SysMB:     round1(float64(ms.Sys) / (1 << 20)),
			Goroutine: runtime.NumGoroutine(),
			FDs:       countFDs(),
			GCCount:   ms.NumGC,
			NumCPU:    runtime.NumCPU(),
		},
	}
	if h != nil {
		sc.Uptime = int64(time.Since(h.started).Seconds())
		st := h.stats()
		sc.Collect = SelfCollect{
			Ticks:   st.Ticks,
			LastMs:  round1(st.LastMs),
			MaxMs:   round1(st.MaxMs),
			AvgMs:   round1(st.AvgMs),
			IdleSec: st.IdleSec,
			Procs:   st.Procs,
			Conts:   st.Conts,
			Conns:   st.Conns,
		}
	}
	if peers != nil {
		sc.Collect.Peers = peers.Count()
		sc.Collect.Pending = peers.Pending()
	}
	if store != nil {
		sc.Storage = store.stats()
	}

	// 地理库是 mmap 进来的，随机查下去文件页会慢慢变驻留、算进 VmRSS。
	// 那些是可回收的干净页，不是泄漏——不扣掉的话，「装了个大库」和
	// 「内存慢慢涨」在数字上长得一模一样，自检就失去意义了。
	rssBudget := sc.Runtime.RSSMB - sc.Runtime.GeoMB
	rssNote := "超出预算通常是连接数暴涨或 SQLite 页缓存没释放"
	rssItem := check("内存 RSS", rssBudget, budgetRSSMB, "MB", rssNote)
	// 显示真实总量（VmRSS 是多少就写多少），判定用扣掉映射后的值。
	rssItem.Value = fmt.Sprintf("%sMB", fmtNum(sc.Runtime.RSSMB))
	if sc.Runtime.GeoMB >= 1 {
		tail := fmt.Sprintf("其中 %.0fMB 是地理库映射（可回收），按 %.0fMB 计预算",
			sc.Runtime.GeoMB, rssBudget)
		if rssItem.Level != "ok" {
			tail = rssNote + "；" + tail
		}
		rssItem.Note = tail
	}

	sc.Checks = append(sc.Checks,
		rssItem,
		check("goroutine", float64(sc.Runtime.Goroutine), budgetGoroutine, "",
			"持续上涨说明有泄漏，重点看 DNS 反查和 netlink"),
	)
	// 没有 /proc 的环境（比如开发机上跑 CLI）读不到 fd，不显示这一项，
	// 免得「0 个 fd」被误读成「很健康」。
	if sc.Runtime.FDs > 0 {
		sc.Checks = append(sc.Checks, check("文件描述符", float64(sc.Runtime.FDs), budgetFDs, "",
			"泄漏会让进程在几天后无法打开任何新文件"))
	}
	if store != nil {
		sc.Checks = append(sc.Checks, check("数据库体积", sc.Storage.DBSizeMB, budgetDBMB, "MB",
			"超出说明保留期没生效，检查 Purge 是否在跑"))
	} else {
		sc.Checks = append(sc.Checks, SelfCheckItem{
			Name: "数据库", Level: "warn", Value: "不可用",
			Note: "历史功能已停用，实时监控不受影响",
		})
	}
	// 没跑过采集（比如 CLI 模式）就没有耗时数据，不显示这项检查
	if sc.Collect.Ticks > 0 {
		sc.Checks = append(sc.Checks, check("单次采集耗时", sc.Collect.MaxMs, budgetTickMs, "ms",
			"超过 1000ms 会开始丢采样，速率显示偏低"))
	}

	if sc.Collect.IdleSec > 10 && sc.Collect.Ticks > 0 {
		sc.Checks = append(sc.Checks, SelfCheckItem{
			Name: "采集循环", Level: "bad",
			Value: fmt.Sprintf("%d 秒没动", sc.Collect.IdleSec),
			Note:  "采集已经停摆，通常是 netlink 或 DNS 卡住了",
		})
	}

	sc.Verdict = "ok"
	for _, c := range sc.Checks {
		if c.Level == "bad" {
			sc.Verdict = "bad"
			break
		}
		if c.Level == "warn" {
			sc.Verdict = "warn"
		}
	}
	return sc
}

func check(name string, v, budget float64, unit, note string) SelfCheckItem {
	item := SelfCheckItem{
		Name:  name,
		Level: "ok",
		Value: fmt.Sprintf("%s%s", fmtNum(v), unit),
	}
	switch {
	case v > budget*1.5:
		item.Level = "bad"
		item.Note = note
	case v > budget:
		item.Level = "warn"
		item.Note = note
	}
	if item.Level != "ok" {
		item.Value += fmt.Sprintf("（预算 %s%s）", fmtNum(budget), unit)
	}
	return item
}

func fmtNum(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}

// readRSSMB 读 /proc/self/status 的 VmRSS。
// 用 VmRSS 而不是 runtime.MemStats：前者是内核记账的实际驻留内存，
// 后者只算 Go 堆，漏掉了 mmap 和未归还的页。
func readRSSMB() float64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			if kb, err := strconv.ParseFloat(f[1], 64); err == nil {
				return kb / 1024
			}
		}
	}
	return 0
}

// readGeoRSSMB 统计 mmdb 映射占了多少驻留内存。
func readGeoRSSMB() float64 {
	b, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		return 0
	}
	return parseGeoRSS(string(b))
}

// parseGeoRSS 从 smaps 文本里累加 .mmdb 映射的 Rss。
//
// smaps 的格式是「映射头 + 若干属性行」，两者都从第 0 列开始，靠缩进分不开：
//
//	7f2c0000-7f2c0300 r--p 00000000 08:01 5678  /path/GeoLite2-City.mmdb
//	Size:             49152 kB
//	Rss:               8192 kB
//
// 区分办法是看第一个字段：映射头是「起址-止址」，里面一定有 `-`；属性行是 `Rss:`。
func parseGeoRSS(smaps string) float64 {
	var kb float64
	inGeo := false
	for _, line := range strings.Split(smaps, "\n") {
		if line == "" {
			continue
		}
		sp := strings.IndexByte(line, ' ')
		if sp > 0 && strings.ContainsRune(line[:sp], '-') {
			inGeo = strings.Contains(line, ".mmdb")
			continue
		}
		if !inGeo || !strings.HasPrefix(line, "Rss:") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			if v, err := strconv.ParseFloat(f[1], 64); err == nil {
				kb += v
			}
		}
	}
	return kb / 1024
}

func countFDs() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(ents)
}

// ---- Hub 统计 ----

type hubStats struct {
	Ticks   int64
	LastMs  float64
	MaxMs   float64
	AvgMs   float64
	IdleSec int64
	Procs   int
	Conts   int
	Conns   int
}

func (h *Hub) stats() hubStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	s := hubStats{
		Ticks:  int64(h.tickN),
		LastMs: float64(h.tickLast.Microseconds()) / 1000,
		MaxMs:  float64(h.tickMax.Microseconds()) / 1000,
		Procs:  len(h.procTot),
		Conts:  len(h.contTot),
	}
	if h.tickN > 0 {
		s.AvgMs = float64(h.tickSum.Microseconds()) / 1000 / float64(h.tickN)
	}
	if h.tickAt > 0 {
		s.IdleSec = time.Now().Unix() - h.tickAt
	}
	if h.snap != nil {
		s.Conns = len(h.snap.Conns)
	}
	return s
}

// ---- 存储统计 ----

func (s *Store) stats() SelfStorage {
	info := SelfStorage{Path: s.path}
	if st, err := os.Stat(s.path); err == nil {
		info.DBSizeMB = round1(float64(st.Size()) / (1 << 20))
	}
	if st, err := os.Stat(s.path + "-wal"); err == nil {
		info.WALSizeMB = round1(float64(st.Size()) / (1 << 20))
	}
	rows, err := s.db.Query(`SELECT gran, COUNT(*) FROM agg GROUP BY gran`)
	if err == nil {
		for rows.Next() {
			var g string
			var n int64
			if rows.Scan(&g, &n) == nil {
				switch g {
				case "1m":
					info.Rows1m = n
				case "1h":
					info.Rows1h = n
				case "1d":
					info.Rows1d = n
				}
			}
		}
		rows.Close()
	}
	if n, err := s.countRules(); err == nil {
		info.Rules = n
	}
	info.OK = true
	return info
}

func (s *Store) countRules() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM rule`).Scan(&n)
	return n, err
}

// ---- 文本输出（给 CLI 用） ----

// padRight 按**显示宽度**补空格。Go 的 %-14s 是按字节算的，
// 中文一个字占 3 字节但只显示 2 列，直接用会歪得没法看。
func padRight(s string, width int) string {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func runeWidth(r rune) int {
	switch {
	case r < 0x1100:
		return 1
	case r >= 0x1100 && r <= 0x115F,
		r >= 0x2E80 && r <= 0xA4CF,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE6F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6:
		return 2
	}
	return 1
}

func (sc *SelfCheck) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "流量哨兵 %s · 自检\n", sc.Version)
	if sc.Uptime > 0 {
		fmt.Fprintf(&b, "已运行 %s · %s\n\n", humanDur(sc.Uptime), sc.TS)
	} else {
		fmt.Fprintf(&b, "%s\n\n", sc.TS)
	}

	row := func(k, v string) {
		fmt.Fprintf(&b, "  %s%s\n", padRight(k, 16), v)
	}

	b.WriteString("运行时\n")
	row("RSS", fmt.Sprintf("%.1f MB", sc.Runtime.RSSMB))
	// 把地理库占的那部分单独列一行：48MB 的 City 库映射进来后，
	// 「RSS 60MB」和「RSS 12MB」在体感上是两回事，但都不是泄漏。
	if sc.Runtime.GeoMB >= 1 {
		row("其中地理库", fmt.Sprintf("%.1f MB（mmap，可回收）", sc.Runtime.GeoMB))
	}
	row("goroutine", strconv.Itoa(sc.Runtime.Goroutine))
	if sc.Runtime.FDs > 0 {
		row("文件描述符", strconv.Itoa(sc.Runtime.FDs))
	}
	row("堆 / 系统", fmt.Sprintf("%.1f MB / %.1f MB", sc.Runtime.HeapMB, sc.Runtime.SysMB))
	row("GC / 核数", fmt.Sprintf("%d 次 / %d 核", sc.Runtime.GCCount, sc.Runtime.NumCPU))

	if sc.Collect.Ticks > 0 {
		b.WriteString("\n采集\n")
		row("次数", strconv.FormatInt(sc.Collect.Ticks, 10))
		row("最近 / 最慢", fmt.Sprintf("%.1fms / %.1fms", sc.Collect.LastMs, sc.Collect.MaxMs))
		row("平均", fmt.Sprintf("%.1fms", sc.Collect.AvgMs))
		row("跟踪对象", fmt.Sprintf("进程 %d · 容器 %d · 连接 %d",
			sc.Collect.Procs, sc.Collect.Conts, sc.Collect.Conns))
		row("外联对端", fmt.Sprintf("%d 条（待裁决 %d）", sc.Collect.Peers, sc.Collect.Pending))
	}

	if sc.Storage.Path != "" {
		b.WriteString("\n存储\n")
		row("数据库", fmt.Sprintf("%.1f MB（WAL %.1f MB）", sc.Storage.DBSizeMB, sc.Storage.WALSizeMB))
		row("行数", fmt.Sprintf("1m %d · 1h %d · 1d %d",
			sc.Storage.Rows1m, sc.Storage.Rows1h, sc.Storage.Rows1d))
		row("规则", fmt.Sprintf("%d 条", sc.Storage.Rules))
	}

	b.WriteString("\n检查项\n")
	for _, c := range sc.Checks {
		mark := "✓"
		switch c.Level {
		case "warn":
			mark = "!"
		case "bad":
			mark = "✗"
		}
		fmt.Fprintf(&b, "  %s %s%s\n", mark, padRight(c.Name, 16), c.Value)
		// 正常项也可能带说明（比如「其中 48MB 是地理库映射」），
		// 那句正是让用户别把 mmap 当成泄漏的关键，不能只在异常时才印。
		if c.Note != "" {
			fmt.Fprintf(&b, "    %s\n", c.Note)
		}
	}
	fmt.Fprintf(&b, "\n结论：%s\n", verdictText(sc.Verdict))
	return b.String()
}

func verdictText(v string) string {
	switch v {
	case "ok":
		return "全部正常"
	case "warn":
		return "有项目超出预算，但还不影响使用"
	default:
		return "有项目异常，需要处理"
	}
}

func humanDur(s int64) string {
	if s < 60 {
		return strconv.FormatInt(s, 10) + " 秒"
	}
	if s < 3600 {
		return fmt.Sprintf("%d 分 %d 秒", s/60, s%60)
	}
	if s < 86400 {
		return fmt.Sprintf("%d 小时 %d 分", s/3600, s%3600/60)
	}
	return fmt.Sprintf("%d 天 %d 小时", s/86400, s%86400/3600)
}

// resolveVarDir 在没显式指定时猜一下数据目录，方便 SSH 里直接跑 selfcheck。
func resolveVarDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, p := range []string{
		"/var/apps/fnnetmon/var",
		filepath.Join("/tmp", "fnnetmon"),
	} {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return "/tmp/fnnetmon"
}
