package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// appRoots 是 fnOS 放置应用的目录。fpk 装好之后的结构是
//
//	/var/apps/<appname>/manifest      ← 里面有一行 display_name = 流量哨兵
//	/var/apps/<appname>/app/bin/xxx
//	/var/apps/<appname>/target -> /usr/local/apps/@appcenter/<appname>
//
// 所以「可执行文件在哪个应用目录下」就是最可靠的服务归属依据。
// 目录不存在时（开发机上跑、或者以后 fnOS 换了布局）整套逻辑自动降级到
// appcenter-cli、systemd 单元名、可执行文件名，不会因此算错或崩掉。
var appRoots = []string{"/var/apps", "/usr/trim/apps"}

// appBinSegments 是可执行文件所在的那一层目录名。
//
// 判断依据是路径里有没有 `@appcenter` / `@appstore` 这一段，后面紧跟应用名：
//
//	/usr/local/apps/@appcenter/trim.photos/trim-photos   ← 系统分区
//	/vol1/@appcenter/baidu.netdisk/target/bin/x          ← 装到存储卷上
//	/vol1/@appstore/xxx/...                              ← 应用商店下载的包
//
// 不能只写死 /var/apps 前缀：/proc/<pid>/exe 读到的是**软链解析后**的真实路径，
// 而 /var/apps/<pkg>/target 恰恰是个指向 /usr/local/apps/@appcenter/<pkg> 的软链。
// 早期版本只认 /var/apps/，结果官方应用一个都匹配不上，全落到 systemd 单元名
// （trim_app_center 之类）或者可执行文件名（trim-photos）上——这就是界面上
// 出现 trim.xxx 的真正原因。
var appBinSegments = map[string]bool{"@appcenter": true, "@appstore": true}

// appCenterCLIPaths 是应用中心 CLI 可能的位置。systemd 下的 PATH 往往很短，
// 直接 exec.LookPath 有可能找不到，所以先按绝对路径试一遍。
var appCenterCLIPaths = []string{
	"/usr/bin/appcenter-cli",
	"/usr/local/bin/appcenter-cli",
	"/usr/sbin/appcenter-cli",
	"/usr/local/sbin/appcenter-cli",
	"/usr/trim/bin/appcenter-cli",
}

// ServiceIndex 把进程身份翻译成「用户认得出的服务名」。
//
// 为什么不用 comm：comm 是内核给的 15 字节名字，同一个应用的不同进程可能是
// node / python3 / ffmpeg，按 comm 分组会把一个服务拆成十几行，正好和
// 「一眼看出谁在偷跑」相反。
//
// 名字有四个来源，优先级从高到低：
//
//	center  appcenter-cli list  ← 应用中心自己维护的已装列表，最权威
//	names   /var/apps/<pkg>/manifest 的 display_name
//	        /var/apps/<pkg>/app/ui/config 的 title
//	        appnames.go 里的内置表
//	单元名   cgroup 里的 .service 段
//	文件名   可执行文件的 basename
type ServiceIndex struct {
	mu     sync.RWMutex
	root   string            // 命中的应用根目录，空表示没找到
	names  map[string]string // 应用包名 → 展示名（本地可读到的）
	srcOf  map[string]string // 应用包名 → 名字是从哪读出来的
	center map[string]string // 应用包名 → 展示名（appcenter-cli 给的）
	cliErr string            // 最近一次 appcenter-cli 失败的原因，给自检看
	cliAt  time.Time
	built  time.Time

	cliOnce sync.Once
}

func NewServiceIndex() *ServiceIndex {
	s := &ServiceIndex{
		names:  map[string]string{},
		srcOf:  map[string]string{},
		center: map[string]string{},
	}
	for _, r := range appRoots {
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			s.root = r
			break
		}
	}
	s.Refresh()
	return s
}

// Refresh 重扫应用目录。只读每个应用的 manifest 和入口配置，几十个应用也就几毫秒，
// 但没必要每秒做，挂到 30 秒的 ticker 上。
func (s *ServiceIndex) Refresh() {
	s.mu.RLock()
	root := s.root
	s.mu.RUnlock()
	if root == "" {
		return
	}
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	names := make(map[string]string, len(ents))
	srcOf := make(map[string]string, len(ents))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pkg := e.Name()
		name, src := localAppName(filepath.Join(root, pkg), pkg)
		if name == "" {
			continue
		}
		names[pkg] = name
		srcOf[pkg] = src
	}
	s.mu.Lock()
	s.names = names
	s.srcOf = srcOf
	s.built = time.Now()
	s.mu.Unlock()
}

// localAppName 按 manifest → 入口配置 → 内置表 的顺序取一个应用的名字。
//
// 顺序里有个容易搞错的点：manifest 的 appname 是**应用唯一标识**（官方文档原话），
// 不是展示名。它经常就等于目录名（appname="demo.app" 而目录也叫 demo.app），
// 这时候拿它当名字等于什么都没读到。所以 appname 排到入口 title 后面，
// 而且只在它和包名不一样时才用。
//
// 三种回落该改的地方不一样，所以要把来源一起返回：
// manifest 读不到是权限或布局问题，入口配置没 title 是打包问题，
// 落到内置表说明这台机器上根本读不到这个应用的元数据。
func localAppName(dir, pkg string) (name, src string) {
	disp, appname, ok := parseManifest(filepath.Join(dir, "manifest"))
	switch {
	case disp != "":
		return disp, "display_name"
	case !ok:
		src = "缺 manifest"
	default:
		src = "manifest 无名字"
	}
	if t := readUIConfigTitle(dir); t != "" {
		return t, "入口 title"
	}
	if appname != "" && appname != pkg {
		return appname, "appname"
	}
	if v := builtinName(pkg); v != "" {
		return v, "内置表"
	}
	return "", src
}

// readUIConfigTitle 读应用入口配置里的 title。
//
// app/ui/config 是桌面图标的定义，结构是 {"url": {"<id>": {"title": ...}}}。
// 它和 manifest 是两个文件，打包时容易只改一个；manifest 缺 display_name 时
// 这里往往还有名字，比直接回落到包名好看得多。
//
// desktop_uidir 默认 ui，但也见过写成 app/ui 的，两个位置都试一下。
func readUIConfigTitle(dir string) string {
	for _, rel := range []string{"app/ui/config", "ui/config"} {
		b, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil || len(b) > 64<<10 {
			continue
		}
		var cfg struct {
			URL map[string]struct {
				Title     string `json:"title"`
				NoDisplay bool   `json:"noDisplay"`
			} `json:".url"`
		}
		if json.Unmarshal(b, &cfg) != nil || len(cfg.URL) == 0 {
			continue
		}
		// map 迭代顺序是随机的，先排序再取，否则同一个应用每次刷新可能换名字
		ids := make([]string, 0, len(cfg.URL))
		for id := range cfg.URL {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			ent := cfg.URL[id]
			if ent.NoDisplay || ent.Title == "" {
				continue
			}
			return strings.TrimSpace(ent.Title)
		}
	}
	return ""
}

// StartAppCenterWatch 起一个后台循环，定期问应用中心要已装应用列表。
//
// 为什么要单独一条 goroutine：appcenter-cli 是个外部进程，冷启动 + 查库
// 可能要几百毫秒到几秒。放进采集 tick 里会直接顶爆「单 tick ≤ 500ms」的预算，
// 表现就是流量图每秒卡一下。这里只更新一个 map，读侧加锁取，互不影响。
func (s *ServiceIndex) StartAppCenterWatch(interval time.Duration) {
	s.cliOnce.Do(func() {
		go func() {
			s.refreshAppCenterOnce()
			t := time.NewTicker(interval)
			defer t.Stop()
			for range t.C {
				s.refreshAppCenterOnce()
			}
		}()
	})
}

// refreshAppCenterOnce 调一次 appcenter-cli list 并换掉 center 表。
func (s *ServiceIndex) refreshAppCenterOnce() {
	out, err := runAppCenterList()
	if err != nil {
		s.mu.Lock()
		s.cliErr = err.Error()
		s.cliAt = time.Now()
		s.mu.Unlock()
		return
	}
	m := parseAppCenterList(out)
	s.mu.Lock()
	// 解析出 0 条时不要把原来那份清掉：CLI 升级换了输出格式的话，
	// 清空会让所有应用瞬间退回包名，比留着旧数据难看得多。
	if len(m) > 0 {
		s.center = m
	}
	s.cliErr = ""
	s.cliAt = time.Now()
	s.mu.Unlock()
}

// runAppCenterList 跑 `appcenter-cli list`，返回原始输出。
func runAppCenterList() (string, error) {
	bin := ""
	for _, p := range appCenterCLIPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			bin = p
			break
		}
	}
	if bin == "" {
		if p, err := exec.LookPath("appcenter-cli"); err == nil {
			bin = p
		}
	}
	if bin == "" {
		return "", errors.New("找不到 appcenter-cli")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "list").Output()
	if err != nil {
		return "", errors.New("appcenter-cli list 失败: " + err.Error())
	}
	return string(out), nil
}

// parseAppCenterList 解析 `appcenter-cli list` 的表格输出。
//
// 真机上的样子（清理精灵也是这么切的）：
//
//	APPNAME       │ DISPLAY NAME  │ VERSION
//	trim.music    │ 音乐          │ 1.2.3
//	fnnetmon      │ 流量哨兵      │ 0.9.4
//
// 所以按竖线切、第一列是包名、第二列是展示名。分隔线用的是 ┼ 不是 │，
// 切出来只有一段，自然被丢掉。表头第一列以 APP 开头，单独排掉。
func parseAppCenterList(out string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := splitTableRow(line)
		if len(fields) < 2 {
			continue
		}
		pkg, name := fields[0], fields[1]
		if !looksLikeAppPkg(pkg) {
			continue
		}
		if name == "" {
			name = pkg
		}
		m[pkg] = name
	}
	return m
}

// splitTableRow 按竖线切一行表格，去掉空字段。全角和半角竖线都认。
func splitTableRow(line string) []string {
	parts := strings.FieldsFunc(line, func(r rune) bool { return r == '│' || r == '|' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// looksLikeAppPkg 排除表头和分隔线。
//
// 只认「第一个字符是字母或数字」的行：分隔线是 ─ ┼ ┌ 这类制表符，
// 表头是 APPNAME / NAME / 应用 之类的固定词。
func looksLikeAppPkg(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
		return false
	}
	switch strings.ToLower(s) {
	case "app", "appname", "app_name", "name", "package", "pkg", "应用", "包名", "应用名":
		return false
	}
	return true
}

// Status 供自检和调试用。
func (s *ServiceIndex) Status() (root string, apps int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.root, len(s.names)
}

// CenterStatus 报告 appcenter-cli 这条来源的状态，给 /api/selfcheck 用。
func (s *ServiceIndex) CenterStatus() (apps int, at time.Time, errMsg string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.center), s.cliAt, s.cliErr
}

// Name 返回这个进程所属的服务名。返回空表示调用方应该用别的名字（容器）。
func (s *ServiceIndex) Name(info *ProcInfo) string {
	if info == nil {
		return ""
	}
	// 容器内进程交给调用方用容器名，否则会把「一个容器」拆成它内部的十几个进程
	if info.ContainerID != "" {
		return ""
	}
	if pkg := s.pkgOf(info.Exe); pkg != "" {
		return s.resolve(pkg)
	}
	if u := unitName(info.Cgroup); u != "" {
		// systemd 单元名和包名不一定一致（trim-photos vs trim.photos），
		// 能查到就用查到的，查不到再用单元名本身。
		if n := s.resolveName(u); n != "" {
			return n
		}
		return u
	}
	if info.Exe != "" {
		base := filepath.Base(info.Exe)
		if n := s.resolveName(base); n != "" {
			return n
		}
		return base
	}
	return info.Name
}

// resolve 把一个应用包名翻成展示名，四个来源依次尝试，最后兜底用包名本身。
func (s *ServiceIndex) resolve(pkg string) string {
	if n := s.resolveName(pkg); n != "" {
		return n
	}
	return pkg
}

// resolveName 只查，不兜底。查不到返回空。
func (s *ServiceIndex) resolveName(key string) string {
	if key == "" {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if n := mapLookup(s.center, key); n != "" {
		return n
	}
	if n := mapLookup(s.names, key); n != "" {
		return n
	}
	return builtinName(key)
}

// mapLookup 依次试 原样 → 全小写 → 把 - 和 _ 归一成 . 。
//
// 最后一档是为了对齐 systemd 单元名和可执行文件名：
// 应用目录叫 trim.photos，它的进程 exe 叫 trim-photos，
// 单元名可能是 trim-photos.service，直接查是查不到的。
func mapLookup(m map[string]string, key string) string {
	if v, ok := m[key]; ok {
		return v
	}
	low := strings.ToLower(key)
	if v, ok := m[low]; ok {
		return v
	}
	if norm := strings.NewReplacer("-", ".", "_", ".").Replace(low); norm != low {
		if v, ok := m[norm]; ok {
			return v
		}
	}
	return ""
}

// appPkgOf 从可执行文件路径里取出应用包名，取不到返回空。
//
//	/var/apps/<pkg>/...            → <pkg>
//	.../@appcenter/<pkg>/...       → <pkg>
//	.../@appstore/<pkg>/...        → <pkg>
func appPkgOf(exe string) string { return appPkgOfRoot(exe, "") }

// pkgOf 是 appPkgOf 的实例版：先按本机实际探测到的应用根目录切一刀。
//
// 两档都要，因为它们覆盖的是同一条路径的两个阶段：
//   - root（/var/apps/<pkg>/...）是安装目录本身；
//   - @appcenter/<pkg>/... 是 /var/apps/<pkg>/target 这个软链解析后的真实位置。
//
// 只按 root 切的话，软链一解析就切不中了——这正是官方应用一个都归不到位的根因。
func (s *ServiceIndex) pkgOf(exe string) string {
	s.mu.RLock()
	root := s.root
	s.mu.RUnlock()
	return appPkgOfRoot(exe, root)
}

func appPkgOfRoot(exe, root string) string {
	if exe == "" {
		return ""
	}
	if root != "" {
		if rel, ok := strings.CutPrefix(exe, strings.TrimSuffix(root, "/")+"/"); ok {
			if pkg, _, _ := strings.Cut(rel, "/"); pkg != "" {
				return pkg
			}
		}
	}
	if rel, ok := strings.CutPrefix(exe, "/var/apps/"); ok {
		pkg, _, _ := strings.Cut(rel, "/")
		return pkg
	}
	segs := strings.Split(exe, "/")
	for i := 0; i+1 < len(segs); i++ {
		if appBinSegments[segs[i]] {
			return segs[i+1]
		}
	}
	return ""
}

// unitName 从 cgroup 路径里取 systemd 单元名。
//
// 取「第一个 .service 段」而不是最后一段：cgroup v2 会把子作用域挂在服务下面，
// 形如 /system.slice/trim-media.service/xxx.scope，最后一段是内部作用域，
// 拿它当服务名毫无意义。
//
// .scope 一律不用：宿主机上能见到的 scope 基本是 session-N.scope（SSH 登录会话）
// 和 docker-<id>.scope（已由容器分支处理），拿来当服务名只会制造噪音。
func unitName(cg string) string {
	if cg == "" {
		return ""
	}
	for _, seg := range strings.Split(cg, "/") {
		if seg == "" || !strings.HasSuffix(seg, ".service") {
			continue
		}
		name := strings.TrimSuffix(seg, ".service")
		if name == "" || strings.HasPrefix(name, "user@") {
			continue
		}
		return name
	}
	return ""
}

// parseManifestName 从 fpk 的 manifest（ini 风格）里读展示名。
// display_name 优先，其次 appname，都没有就返回空。
func parseManifestName(path string) string {
	disp, appname, _ := parseManifest(path)
	if disp != "" {
		return disp
	}
	return appname
}

// parseManifest 读出 manifest 里的 display_name 和 appname，并告诉调用方文件在不在。
//
// 和 parseManifestName 分开是因为核对工具（fnnetmon svc）要区分三种情况：
// 文件没有、有文件但没 display_name、两个键都没有——它们回落到不同的名字，
// 只看最终结果分不出是哪一种，也就不知道该改哪里。
func parseManifest(path string) (displayName, appname string, ok bool) {
	st, err := os.Stat(path)
	if err != nil || st.Size() > 64<<10 {
		return "", "", false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(k) {
		case "display_name":
			if v = manifestValue(v); v != "" {
				return v, appname, true
			}
		case "appname":
			appname = manifestValue(v)
		}
	}
	return "", appname, true
}

// manifestValue 去掉值两边的空白和引号。
//
// 官方文档里的示例是裸值（appname=HelloFnos），但真机上大量 manifest 写成
// appname="trim.vm" / display_name="音乐"——fpk 打包工具两派都有。不去引号的话
// 界面上会显示成带引号的 `"音乐"`，而且看不出哪里错了。
func manifestValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if q := v[0]; (q == '"' || q == '\'') && v[len(v)-1] == q {
			return strings.TrimSpace(v[1 : len(v)-1])
		}
	}
	return v
}
