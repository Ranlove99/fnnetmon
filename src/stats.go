package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// 未归因下钻。
//
// 排行里的「未归因」是 `网卡总量 − 已归因`，数字大但说不出所以然。实测真机上
// 这个差额能到 400KB/s，用户第一反应是「有东西抓不到」——对，但不知道是什么。
//
// 来源有四类，前两类能用 nftables 的计数器直接量出来：
//  1. UDP：inet_diag 不返回字节计数，这些流量天生进不了归因（nft 按协议数）
//  2. 内核转发：没有进程持有 socket，谁都不算它的（forward 链单独数）
//  3. 无主 socket：进程已退出但 socket 还在
//  4. 采样间隙：1 秒一次，突发流量会漏
//
// 这张表**只统计、不拦截**：policy 永远是 accept，没有任何 drop 规则，
// 即使整张表写坏了也只是不统计，不会影响转发——和拦截表 fnnetmon 完全分开，
// 因为观测和拦截的风险差一个数量级。
const (
	statTable = "fnnetmon_stat"
	statIface = "" // 留空表示所有网卡；只有 lo 被排除

	// nft 的 lexer 把 fwd 当关键字（fwd to <dev> 语句），写成 `chain fwd`
	// 会直接报 `syntax error, unexpected fwd, expecting string`——0.9.8 在
	// fnOS x86 的 server.log 里实测到，整块下钻因此静默关闭。链名一律加
	// fnm_ 前缀，别拿单个英文单词当链名；解析按 counter.comment 归类，
	// 所以老版本建的 out/fwd 旧表照样能读。
	statChainOut = "fnm_out"
	statChainFwd = "fnm_fwd"
)

type UnattrParts struct {
	Available bool    `json:"available"`
	Reason    string  `json:"reason,omitempty"`
	UDP       float64 `json:"udp"` // B/s
	TCP       float64 `json:"tcp"` // B/s
	Fwd       float64 `json:"fwd"` // B/s 内核转发
	Out       float64 `json:"out"` // B/s 出向合计（不含 lo）
	At        string  `json:"at,omitempty"`
}

type statCounters struct {
	tcp, udp, fwd uint64
	valid         bool
}

type StatSampler struct {
	mu     sync.Mutex
	avail  bool
	reason string
	mode   string // 当前生效的建表方案
	prev   statCounters
	prevAt time.Time
	rate   UnattrParts
	busy   bool
}

func NewStatSampler() *StatSampler { return &StatSampler{} }

type statVariant struct {
	name   string
	script string
}

// statScript 生成建表脚本。注释写在 counter 上，读的时候按 comment 归类——
// 比按规则顺序对应可靠（以后加一条规则不会把归类错位）。
// withFwd=false 用于降级：有些环境的 nft / 内核不接受 inet family 的 forward
// 钩子，这时至少把出向的 TCP/UDP 数出来，别把整块下钻关掉。
func statScript(withFwd bool) string {
	lo := ""
	if statIface != "" {
		lo = fmt.Sprintf(`oifname != "lo" oifname != "%s" `, statIface)
	} else {
		lo = `oifname != "lo" `
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n  chain %s {\n", statTable, statChainOut)
	b.WriteString("    type filter hook output priority -150; policy accept;\n")
	fmt.Fprintf(&b, "    %smeta l4proto tcp counter comment \"tcp\"\n", lo)
	fmt.Fprintf(&b, "    %smeta l4proto udp counter comment \"udp\"\n", lo)
	b.WriteString("  }\n")
	if withFwd {
		fmt.Fprintf(&b, "  chain %s {\n", statChainFwd)
		b.WriteString("    type filter hook forward priority -150; policy accept;\n")
		b.WriteString("    counter comment \"fwd\"\n  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// statVariants 按「信息量从多到少」排，依次尝试，第一个能用的就落地。
// 不同 fnOS 机器上的 nft 版本差异比想象中大，别指望一次建表处处成功。
func statVariants() []statVariant {
	return []statVariant{
		{"出向 + 转发", statScript(true)},
		{"仅出向", statScript(false)},
	}
}

// tryStatVariants 依次试每个方案，返回成功的名字和被跳过的方案的原因。
// try 由调用方提供（真机上就是 nft 语法预检 + 建表），测试里传假函数即可。
func tryStatVariants(try func(statVariant) error) (string, []string) {
	var notes []string
	for _, v := range statVariants() {
		if err := try(v); err != nil {
			notes = append(notes, v.name+"："+firstLine(err.Error()))
			continue
		}
		return v.name, notes
	}
	return "", notes
}

// Ensure 建表。表已经存在且计数器齐全就什么都不做（幂等），表被人删了下次会重建。
func (s *StatSampler) Ensure() error {
	// 只判「表在不在」不够：旧版本可能留下半张表（建到一半失败），
	// 那样 Sample 会一直报「表里没有计数器」，三次后回到这里又直接返回，死循环。
	if out, err := runCmd("nft", "-j", "list", "table", "inet", statTable); err == nil {
		if parseStatCounters(out).valid {
			s.setAvail(true, "")
			return nil
		}
		_, _ = runCmd("nft", "delete", "table", "inet", statTable)
	}

	name, notes := tryStatVariants(func(v statVariant) error {
		// 和拦截表一个规矩：先语法预检，宁可不上，也不留半张表
		if _, err := runNft(v.script, true); err != nil {
			return fmt.Errorf("语法预检失败：%w", err)
		}
		if _, err := runNft(v.script, false); err != nil {
			// 应用阶段也可能只写进去一半，清干净再试下一个方案
			_, _ = runCmd("nft", "delete", "table", "inet", statTable)
			return fmt.Errorf("建表失败：%w", err)
		}
		return nil
	})
	if name == "" {
		msg := "所有建表方案都失败：" + strings.Join(notes, "；")
		s.setAvail(false, msg)
		return fmt.Errorf("%s", msg)
	}
	s.mu.Lock()
	s.mode = name
	s.mu.Unlock()
	s.setAvail(true, "")
	if detail := strings.Join(notes, "；"); detail != "" {
		fmt.Fprintf(os.Stderr, "[fnnetmon] unattr breakdown: 使用「%s」方案（%s）\n", name, detail)
	}
	return nil
}

func (s *StatSampler) setAvail(ok bool, reason string) {
	s.mu.Lock()
	s.avail, s.reason = ok, reason
	s.mu.Unlock()
}

func (s *StatSampler) available() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.avail
}

// Sample 读一次计数器并换算成速率。两次采样之间不够 1 秒就跳过，
// 否则除出来的数字会跳得很厉害。
func (s *StatSampler) Sample() {
	s.mu.Lock()
	if s.busy {
		s.mu.Unlock()
		return
	}
	s.busy = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.busy = false
		s.mu.Unlock()
	}()

	out, err := runCmd("nft", "-j", "list", "table", "inet", statTable)
	if err != nil {
		s.setAvail(false, "读计数器失败："+firstLine(err.Error()))
		return
	}
	cur := parseStatCounters(out)
	if !cur.valid {
		s.setAvail(false, "表里没有计数器（可能被清掉了）")
		return
	}
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	s.avail = true
	s.reason = ""
	// 第一次采样只记基线，不出速率——差值没有参照物
	if !s.prev.valid || s.prevAt.IsZero() {
		s.prev, s.prevAt = cur, now
		return
	}
	sec := now.Sub(s.prevAt).Seconds()
	if sec < 0.5 {
		return
	}
	d := func(a, b uint64) float64 {
		if a < b {
			return 0 // 计数器被重置（表重建过）
		}
		return float64(a-b) / sec
	}
	s.rate = UnattrParts{
		Available: true,
		UDP:       d(cur.udp, s.prev.udp),
		TCP:       d(cur.tcp, s.prev.tcp),
		Fwd:       d(cur.fwd, s.prev.fwd),
		Out:       d(cur.tcp+cur.udp, s.prev.tcp+s.prev.udp),
		At:        now.Format("15:04:05"),
	}
	s.prev, s.prevAt = cur, now
}

func (s *StatSampler) Snapshot() UnattrParts {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.avail {
		return UnattrParts{Reason: s.reason}
	}
	r := s.rate
	r.Available = true
	r.Reason = s.reason
	return r
}

func (s *StatSampler) Clear() {
	if _, err := runCmd("nft", "delete", "table", "inet", statTable); err == nil {
		s.setAvail(false, "")
	}
}

// Run 每 5 秒采一次。挂在自己的 goroutine 上，读失败也只影响这一块，
// 不会拖累 1 秒一次的采集循环。
// 建表失败不再直接退出 goroutine：条件恢复（权限、nft 装好、表被修好）后
// 自己就能回来，不用重启服务。重试日志只在首次打，避免刷屏。
func (s *StatSampler) Run(interval time.Duration, onErr func(string)) {
	if err := s.Ensure(); err != nil && onErr != nil {
		onErr(err.Error())
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	down := 0
	wasDown := !s.available()
	for range t.C {
		if s.available() {
			s.Sample()
			if s.available() {
				if wasDown {
					s.mu.Lock()
					mode := s.mode
					s.mu.Unlock()
					fmt.Fprintf(os.Stderr, "[fnnetmon] unattr breakdown: 已恢复统计（%s）\n", mode)
					wasDown = false
				}
				down = 0
				continue
			}
		}
		wasDown = true
		down++
		// 头 3 个 tick 快试，之后每 12 个 tick（约 1 分钟）慢试，
		// 别为了一个统计功能每 5 秒去敲一次 nft。
		if down > 3 && down%12 != 0 {
			continue
		}
		if err := s.Ensure(); err != nil {
			continue
		}
		down = 0
	}
}

// parseStatCounters 从 `nft -j list table` 的 JSON 里按 comment 归类。
// nft 的 JSON 结构是 {nftables:[{metainfo},{table},{chain},{rule},...]}，
// rule 里的 expr 数组可能包含多个表达式，counter 只是其中一个。
func parseStatCounters(b []byte) statCounters {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Expr []struct {
					Counter *struct {
						Bytes   uint64 `json:"bytes"`
						Comment string `json:"comment"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return statCounters{}
	}
	var c statCounters
	for _, it := range doc.Nftables {
		if it.Rule == nil {
			continue
		}
		for _, e := range it.Rule.Expr {
			if e.Counter == nil {
				continue
			}
			switch strings.TrimSpace(e.Counter.Comment) {
			case "tcp":
				c.tcp += e.Counter.Bytes
				c.valid = true
			case "udp":
				c.udp += e.Counter.Bytes
				c.valid = true
			case "fwd":
				c.fwd += e.Counter.Bytes
				c.valid = true
			}
		}
	}
	return c
}
