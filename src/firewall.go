package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// 本文件是 M5 的主动拦截层。设计原则只有一条：**宁可拦不住，也不能把用户的 NAS 弄断网**。
//
// 具体做法：
//  1. 只操作自己建的 `table inet fnnetmon`，绝不碰别人的规则集；
//  2. 只挂 output 链，policy 永远是 accept —— 失败方向必须是「全放行」；
//  3. 白名单硬编码在链首：lo、私网段、组播、广播，永远 accept。
//     这一条是安全底线：即使规则写错，SSH、fnOS 管理页、内网共享都不受影响；
//  4. 默认不开启（enforce=false），用户显式打开才下发；
//  5. 每次下发前 `nft -c` 做语法校验，整表原子替换；
//  6. 提供 CLI 逃生口 `fnnetmon firewall off`，SSH 里一条命令就能恢复。

const (
	fwTable = "fnnetmon"
	fwChain = "out"
)

// Rule 是一条出向规则。匹配维度是 cgroup（内核 5.13+ 的 meta cgroup），
// 因为 nftables 无法按 PID 匹配，而 cgroup 路径在服务重启后依然稳定。
//
// kind=ip 时按 ip 列匹配；kind=domain 时按 domain 列匹配，
// 下发那一刻才把域名解析成地址列表。域名规则是 CDN 场景的关键：
// 封 tiktok.com 比封它背后的 30 个 IP 有意义得多。
type Rule struct {
	ID      int64  `json:"id"`
	Action  string `json:"action"` // allow | deny
	Proc    string `json:"proc"`   // 展示用
	Cont    string `json:"cont"`
	Cgroup  string `json:"cg"` // 匹配用，如 /system.slice/trim-xxx.service
	IP      string `json:"ip"` // 远端地址或 CIDR，空表示该进程的所有出向
	Port    int    `json:"port"`
	Kind    string `json:"kind"`   // ip | domain
	Domain  string `json:"domain"` // kind=domain 时有效
	IPs     int    `json:"ips"`    // 本次实际展开的地址数（不落库）
	Enabled bool   `json:"enabled"`
	Note    string `json:"note"`
	Created int64  `json:"created"`
	Err     string `json:"err,omitempty"` // 单条规则的下发失败原因
}

type FirewallStatus struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason"`
	Version   string `json:"version"`
	Enforce   bool   `json:"enforce"`
	Rules     int    `json:"rules"`   // 库里启用的规则数
	Applied   int    `json:"applied"` // 真正下到内核的条数
	LastErr   string `json:"last_err"`
	Updated   string `json:"updated"`
	Chain     string `json:"chain"`
}

type Firewall struct {
	mu      sync.Mutex
	avail   bool
	reason  string
	version string
	enforce bool
	applied int
	lastErr string
	updated time.Time
	rules   []Rule // 最近一次下发的规则（含单条 Err）
	dom     *DomainCache
}

func NewFirewall() *Firewall {
	f := &Firewall{}
	f.Probe()
	return f
}

// SetDomainCache 给域名规则提供地址解析来源。不设置的话域名规则一律跳过。
func (f *Firewall) SetDomainCache(d *DomainCache) {
	f.mu.Lock()
	f.dom = d
	f.mu.Unlock()
}

// Probe 探测 nft 是否可用，以及内核是否支持 meta cgroup。
// 不支持 meta cgroup 就没有按进程匹配的能力，只能降级成纯观测。
func (f *Firewall) Probe() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probeLocked()
}

func (f *Firewall) probeLocked() {
	f.avail = false
	f.reason = ""

	if _, err := exec.LookPath("nft"); err != nil {
		f.reason = "系统里没有 nft 命令（fnOS 可能用的是 iptables）"
		return
	}
	if out, err := runCmd("nft", "--version"); err == nil {
		f.version = strings.TrimSpace(string(out))
	}
	// 能不能读规则集（同时验证权限和内核模块）
	if _, err := runCmd("nft", "list", "tables"); err != nil {
		f.reason = "无法读取 nftables 规则集：" + firstLine(err.Error())
		return
	}
	// 真建一张临时表来验证 meta cgroup —— 只查版本号不可靠，
	// 有些发行版编了 nft 但内核没开 CONFIG_NETFILTER_XT_MATCH_CGROUP 对应的支持。
	probe := "table inet fnnetmon_probe {\n  chain c {\n    meta cgroup 1 accept\n  }\n}\n"
	if _, err := runNft(probe, true); err != nil {
		f.reason = "内核不支持 meta cgroup（需要 Linux 5.13+）：" + firstLine(err.Error())
		return
	}
	_, _ = runCmd("nft", "delete", "table", "inet", "fnnetmon_probe")

	f.avail = true
	f.reason = ""
}

// Status 返回当前状态给前端。
func (f *Firewall) Status() FirewallStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := FirewallStatus{
		Available: f.avail,
		Reason:    f.reason,
		Version:   f.version,
		Enforce:   f.enforce,
		Applied:   f.applied,
		LastErr:   f.lastErr,
		Chain:     "table inet " + fwTable,
	}
	if !f.updated.IsZero() {
		st.Updated = f.updated.Format("15:04:05")
	}
	for _, r := range f.rules {
		if r.Enabled && r.Err == "" {
			st.Rules++
		}
	}
	return st
}

// SetEnforce 打开/关闭主动拦截。关闭时会把表删掉，立即恢复全放行。
func (f *Firewall) SetEnforce(on bool, rules []Rule) error {
	f.mu.Lock()
	f.enforce = on
	f.mu.Unlock()
	if !on {
		return f.Clear()
	}
	return f.Apply(rules)
}

// Apply 全量重建规则表。整表原子替换，中途失败等于回到全放行。
func (f *Firewall) Apply(rules []Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.avail {
		return fmt.Errorf("nftables 不可用：%s", f.reason)
	}

	body, applied, perr := renderRules(rules, f.dom)

	// 先删旧表（不存在会报错，忽略）
	_, _ = runCmd("nft", "delete", "table", "inet", fwTable)

	if applied == 0 {
		f.applied = 0
		f.rules = perr
		f.lastErr = ""
		f.updated = time.Now()
		return nil // 没有规则 = 全放行，等同于关闭
	}

	script := "table inet " + fwTable + " {\n  chain " + fwChain + " {\n" +
		"    type filter hook output priority 0; policy accept;\n" + body + "  }\n}\n"

	// 语法校验，不过就不下发。这一步能挡掉绝大多数「把自己拦死」的意外。
	if _, err := runNft(script, true); err != nil {
		f.lastErr = "规则语法校验失败：" + firstLine(err.Error())
		f.rules = perr
		return fmt.Errorf("%s", f.lastErr)
	}
	if _, err := runNft(script, false); err != nil {
		f.lastErr = "下发失败：" + firstLine(err.Error())
		f.rules = perr
		return fmt.Errorf("%s", f.lastErr)
	}

	f.applied = applied
	f.rules = perr
	f.lastErr = ""
	f.updated = time.Now()
	return nil
}

// Clear 删除自己那张表。任何异常路径都应该调它。
func (f *Firewall) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enforce = false
	f.applied = 0
	_, err := runCmd("nft", "delete", "table", "inet", fwTable)
	f.updated = time.Now()
	return err
}

// Reload 规则变动后重新下发。没开拦截时只更新内存状态，不碰内核 ——
// 用户只是改了规则但没启用，不该有任何网络影响。
func (f *Firewall) Reload(rules []Rule) {
	f.mu.Lock()
	on := f.enforce
	f.mu.Unlock()
	if on {
		if err := f.Apply(rules); err != nil {
			fmt.Fprintf(os.Stderr, "[fnnetmon] apply rules failed: %v\n", err)
		}
		return
	}
	f.mu.Lock()
	f.rules = rules
	f.mu.Unlock()
}

// cgroupInodeFn 允许测试替换：测试机通常没有 /sys/fs/cgroup，
// 不替换就没法验证规则语法。
var cgroupInodeFn = cgroupInode

// renderRules 把规则翻译成 nft 语法。返回链体、成功条数、逐条状态。
// dom 为 nil 时域名规则一律跳过 —— 拿不到地址就不能下发，这是硬约束。
func renderRules(rules []Rule, dom *DomainCache) (string, int, []Rule) {
	var b strings.Builder
	out := make([]Rule, 0, len(rules))
	applied := 0
	now := time.Now().Unix()

	// ---- 硬编码白名单，永远在最前 ----
	// 私网段这一条是安全底线：拦住内网 = 连不上路由器/其他设备/管理页。
	b.WriteString("    oifname \"lo\" accept\n")
	b.WriteString("    ip daddr { 127.0.0.0/8, 224.0.0.0/4, 255.255.255.255/32 } accept\n")
	b.WriteString("    ip6 daddr { ::1, ff00::/8 } accept\n")
	b.WriteString("    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } accept\n")
	b.WriteString("    ip6 daddr { fe80::/10, fc00::/7 } accept\n")

	for _, r := range rules {
		if !r.Enabled {
			out = append(out, r)
			continue
		}
		if r.Cgroup == "" {
			r.Err = "缺少 cgroup 路径，无法匹配进程"
			out = append(out, r)
			continue
		}
		ino, err := cgroupInodeFn(r.Cgroup)
		if err != nil {
			r.Err = "cgroup 已不存在（服务可能已卸载或改名）"
			out = append(out, r)
			continue
		}

		var ips []string
		if r.Kind == "domain" {
			if r.Domain == "" {
				r.Err = "域名为空"
				out = append(out, r)
				continue
			}
			if dom == nil {
				r.Err = "域名归因未启用，域名规则无法下发"
				out = append(out, r)
				continue
			}
			ips = dom.IPsFor(r.Domain, now)
			if len(ips) == 0 {
				// 关键安全阀：解析不到地址就跳过。
				// 如果这里继续往下走，就会生成一条「该进程所有出向全丢」的规则，
				// 用户的程序会突然彻底断网，而且看起来像是程序自己坏了。
				r.Err = "域名当前解析不到地址，已跳过（不会裸拦全部出向）"
				out = append(out, r)
				continue
			}
			if len(ips) > maxDomainIPs {
				ips = ips[:maxDomainIPs]
				r.Err = fmt.Sprintf("地址超过 %d 个，已截断", maxDomainIPs)
			}
			r.IPs = len(ips)
		} else if r.IP != "" {
			if err := validCIDR(r.IP); err != nil {
				r.Err = err.Error()
				out = append(out, r)
				continue
			}
			ips = []string{r.IP}
			r.IPs = 1
		}

		exprs, err := ruleExprs(r, ino, ips)
		if err != nil {
			r.Err = err.Error()
			out = append(out, r)
			continue
		}
		for _, e := range exprs {
			b.WriteString("    " + e + "\n")
			applied++
		}
		out = append(out, r)
	}
	return b.String(), applied, out
}

// maxDomainIPs 单个域名最多展开多少个地址。CDN 域名常见 4~16 个，
// 128 已经足够覆盖，再多的多半是解析异常。
const maxDomainIPs = 128

// ruleExpr 是单地址版本的兼容入口，测试和旧调用方用。
func ruleExpr(r Rule, ino uint64) (string, error) {
	var ips []string
	if r.IP != "" {
		if err := validCIDR(r.IP); err != nil {
			return "", err
		}
		ips = []string{r.IP}
	}
	exprs, err := ruleExprs(r, ino, ips)
	if err != nil {
		return "", err
	}
	if len(exprs) == 0 {
		return "", fmt.Errorf("没有可下发的内容")
	}
	return exprs[0], nil
}

// ruleExprs 生成一条或多条 nft 表达式。
// 一个域名可能同时有 IPv4 和 IPv6 地址，必须拆成两条：
// nft 不允许在一个 daddr 集合里混两种地址族。
func ruleExprs(r Rule, ino uint64, ips []string) ([]string, error) {
	action := "drop"
	if r.Action == "allow" {
		action = "accept"
	}
	base := []string{fmt.Sprintf("meta cgroup %d", ino)}
	if r.Port > 0 && r.Port < 65536 {
		// 单独写 `th dport` 会报错：transport header 必须前面有 l4 协议匹配。
		// 规则里不带协议字段，所以这里同时匹配 tcp/udp。
		base = append(base, fmt.Sprintf("meta l4proto { tcp, udp } th dport %d", r.Port))
	}

	if len(ips) == 0 {
		// 不带任何 daddr：该进程的所有出向。只有 kind=ip 且 ip 为空时才允许走到这里。
		parts := append(append([]string{}, base...), "counter", action)
		return []string{strings.Join(parts, " ")}, nil
	}

	var v4, v6 []string
	for _, ip := range ips {
		if strings.Contains(ip, ":") {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}

	emit := func(fam string, list []string) string {
		parts := append([]string{}, base...)
		if len(list) == 1 {
			parts = append(parts, fam+" daddr "+list[0])
		} else {
			parts = append(parts, fam+" daddr { "+strings.Join(list, ", ")+" }")
		}
		parts = append(parts, "counter", action)
		return strings.Join(parts, " ")
	}

	out := make([]string, 0, 2)
	if len(v4) > 0 {
		out = append(out, emit("ip", v4))
	}
	if len(v6) > 0 {
		out = append(out, emit("ip6", v6))
	}
	return out, nil
}

// validCIDR 在拼 nft 语法之前就把非法地址挡掉。
// 只做字符白名单是不够的（"abc" 全是十六进制字符），必须真正解析一次。
func validCIDR(s string) error {
	for _, c := range s {
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
			c == '.' || c == ':' || c == '/'
		if !ok {
			return fmt.Errorf("非法地址：%s", s)
		}
	}
	if strings.Contains(s, "/") {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("非法 CIDR：%s", s)
		}
		return nil
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("非法地址：%s", s)
	}
	return nil
}

// cgroupInode 把 cgroup 路径换成内核里的 inode 号，nft 的 meta cgroup 要的就是它。
func cgroupInode(path string) (uint64, error) {
	if path == "" {
		return 0, fmt.Errorf("空路径")
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/sys/fs/cgroup"+path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Ino), nil
}

// runNft 把脚本通过 stdin 喂给 nft。check=true 时只做语法校验（-c）。
func runNft(script string, check bool) ([]byte, error) {
	args := []string{"-f", "-"}
	if check {
		args = []string{"-c", "-f", "-"}
	}
	cmd := exec.Command("nft", args...)
	cmd.Stdin = strings.NewReader(script)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return out.Bytes(), nil
}

func runCmd(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return out.Bytes(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ---- 规则存储 ----

func (s *Store) ListRules() ([]Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`
SELECT id, action, proc, cont, cgroup, ip, port, kind, domain, enabled, note, created
FROM rule ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		var en int
		if err := rows.Scan(&r.ID, &r.Action, &r.Proc, &r.Cont, &r.Cgroup, &r.IP,
			&r.Port, &r.Kind, &r.Domain, &en, &r.Note, &r.Created); err != nil {
			continue
		}
		if r.Kind == "" {
			r.Kind = "ip"
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, nil
}

func (s *Store) AddRule(r Rule) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Kind == "" {
		r.Kind = "ip"
	}
	res, err := s.db.Exec(`
INSERT INTO rule(action,proc,cont,cgroup,ip,port,kind,domain,enabled,note,created)
VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		r.Action, r.Proc, r.Cont, r.Cgroup, r.IP, r.Port, r.Kind, r.Domain,
		boolInt(r.Enabled), r.Note, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) SetRuleEnabled(id int64, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE rule SET enabled=? WHERE id=?`, boolInt(on), id)
	return err
}

func (s *Store) DeleteRule(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM rule WHERE id=?`, id)
	return err
}

// DeleteAutoRules 删掉由「首次外联裁决」自动生成、且针对同一目标的规则。
// 撤销裁决或忽略记录时必须调它，否则会留下一条没人记得的拦截规则。
// 只删 note 标记的自动规则，用户手动加的规则不动。
//
// ip 和 domain 要同时给：IP 规则是 (ip=X, domain="")，
// 域名规则是 (ip="", domain=Y)。两个都精确匹配才不会误删另一类。
func (s *Store) DeleteAutoRules(proc, ip, domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM rule WHERE proc=? AND note=? AND ip=? AND domain=?`,
		proc, autoRuleNote, ip, domain)
	return err
}

const autoRuleNote = "来自首次外联裁决"

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
