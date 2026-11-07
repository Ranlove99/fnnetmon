package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Report struct {
	GeneratedAt string            `json:"generated_at"`
	Version     string            `json:"app_version"`
	System      SystemInfo        `json:"system"`
	Fnos        map[string]string `json:"fnos"`
	Kernel      KernelCaps        `json:"kernel"`
	Net         NetInfo           `json:"net"`
	Attrib      AttribInfo        `json:"attribution"`
	Docker      DockerInfo        `json:"docker"`
	Runtime     RuntimeInfo       `json:"runtime"`
	Verdict     []Verdict         `json:"verdict"`
	Gateway     map[string]string `json:"gateway,omitempty"`
}

type SystemInfo struct {
	Sysname  string `json:"sysname"`
	Release  string `json:"release"`
	Machine  string `json:"machine"`
	Distro   string `json:"distro"`
	CPUModel string `json:"cpu_model"`
	Cores    int    `json:"cores"`
	MemTotal string `json:"mem_total"`
	Uptime   string `json:"uptime"`
}

type KernelCaps struct {
	BTFPath    string            `json:"btf_path"`
	BTFSize    int64             `json:"btf_size"`
	BTFOK      bool              `json:"btf_ok"`
	BPFSyscall string            `json:"bpf_syscall"`
	BPFOK      bool              `json:"bpf_ok"`
	Tracefs    string            `json:"tracefs"`
	KprobeOK   bool              `json:"kprobe_ok"`
	ConfigFile string            `json:"config_file"`
	Config     map[string]string `json:"config"`
	Sysctl     map[string]string `json:"sysctl"`
	Tools      map[string]string `json:"tools"`
	Lockdown   string            `json:"lockdown"`
}

type NetInfo struct {
	Interfaces  []Iface        `json:"interfaces"`
	DefaultRtr  string         `json:"default_route"`
	ConnTotal   int            `json:"conn_total"`
	ConnByProto map[string]int `json:"conn_by_proto"`
}

type Iface struct {
	Name    string  `json:"name"`
	MAC     string  `json:"mac"`
	State   string  `json:"state"`
	MTU     string  `json:"mtu"`
	Speed   string  `json:"speed"`
	RXBytes uint64  `json:"rx_bytes"`
	TXBytes uint64  `json:"tx_bytes"`
	RXRate  float64 `json:"rx_rate_kbs"`
	TXRate  float64 `json:"tx_rate_kbs"`
	Virtual bool    `json:"virtual"`
}

type AttribInfo struct {
	ProcCount    int     `json:"proc_count"`
	SocketFDs    int     `json:"socket_fds"`
	ScanMs       float64 `json:"scan_ms"`
	ConnMapped   int     `json:"conn_mapped"`
	ConnTotal    int     `json:"conn_total"`
	Coverage     float64 `json:"coverage_pct"`
	CanReadProc1 bool    `json:"can_read_proc1_fd"`
}

type DockerInfo struct {
	SocketExists bool     `json:"socket_exists"`
	APIOK        bool     `json:"api_ok"`
	Version      string   `json:"version"`
	Containers   int      `json:"containers"`
	Names        []string `json:"names"`
	VethCount    int      `json:"veth_count"`
	Error        string   `json:"error,omitempty"`
}

type RuntimeInfo struct {
	EUID  int               `json:"euid"`
	UID   int               `json:"uid"`
	GID   int               `json:"gid"`
	User  string            `json:"user"`
	Exe   string            `json:"exe"`
	GoVer string            `json:"go_version"`
	RSS   string            `json:"rss"`
	Env   map[string]string `json:"env"`
}

type Verdict struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
}

func Collect() *Report {
	r := &Report{
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		Version:     version,
	}
	r.System = collectSystem()
	r.Fnos = collectFnos()
	r.Kernel = collectKernel()
	r.Net = collectNet()
	r.Attrib = collectAttrib()
	r.Docker = collectDocker()
	r.Runtime = collectRuntime()
	r.Verdict = judge(r)
	return r
}

func readFirst(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func osField(path, key string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			v := strings.TrimPrefix(line, key+"=")
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

func collectSystem() SystemInfo {
	sys, rel, mach := uname()
	s := SystemInfo{
		Sysname: sys,
		Release: rel,
		Machine: mach,
		Distro:  osField("/etc/os-release", "PRETTY_NAME"),
		Cores:   runtime.NumCPU(),
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			for _, k := range []string{"model name", "Hardware", "Processor"} {
				if strings.HasPrefix(line, k) {
					s.CPUModel = strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
					break
				}
			}
			if s.CPUModel != "" {
				break
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				f := strings.Fields(line)
				if len(f) >= 2 {
					kb, _ := strconv.ParseFloat(f[1], 64)
					s.MemTotal = fmt.Sprintf("%.1f GB", kb/1024/1024)
				}
			}
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			if sec, err := strconv.ParseFloat(f[0], 64); err == nil {
				d := time.Duration(sec) * time.Second
				s.Uptime = fmt.Sprintf("%dd %dh %dm", int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60)
			}
		}
	}
	return s
}

func collectFnos() map[string]string {
	m := map[string]string{}
	for _, k := range []string{
		"TRIM_APPNAME", "TRIM_APPVER", "TRIM_APP_STATUS", "TRIM_APPDEST",
		"TRIM_PKGETC", "TRIM_PKGVAR", "TRIM_PKGTMP", "TRIM_PKGHOME",
		"TRIM_USERNAME", "TRIM_GROUPNAME", "TRIM_UID", "TRIM_GID",
		"TRIM_RUN_USERNAME", "TRIM_RUN_UID", "TRIM_SERVICE_PORT",
		"TRIM_SYS_VERSION", "TRIM_SYS_ARCH", "TRIM_KERNEL_VERSION",
		"TRIM_SYS_MACHINE_ID", "TRIM_SYS_LANGUAGE",
	} {
		if v := os.Getenv(k); v != "" {
			m[k] = v
		}
	}
	for _, p := range []string{"/etc/fnos-release", "/etc/fnos_version", "/etc/version", "/etc/issue"} {
		if v := readFirst(p); v != "" {
			m[p] = strings.ReplaceAll(v, "\n", " | ")
		}
	}
	if ents, err := os.ReadDir("/var/apps"); err == nil {
		var names []string
		for _, e := range ents {
			if e.IsDir() {
				names = append(names, e.Name())
			}
		}
		m["/var/apps"] = strings.Join(names, ", ")
	}
	return m
}

func collectKernel() KernelCaps {
	k := KernelCaps{Config: map[string]string{}, Sysctl: map[string]string{}, Tools: map[string]string{}}

	k.BTFPath = "/sys/kernel/btf/vmlinux"
	if st, err := os.Stat(k.BTFPath); err == nil {
		k.BTFOK = true
		k.BTFSize = st.Size()
	}

	ok, msg := testBPFSyscall()
	k.BPFOK = ok
	k.BPFSyscall = msg

	for _, p := range []string{"/sys/kernel/tracing/kprobe_events", "/sys/kernel/debug/tracing/kprobe_events"} {
		if _, err := os.Stat(p); err == nil {
			if k.Tracefs == "" {
				k.Tracefs = p
			}
			if f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0); err == nil {
				f.Close()
				k.KprobeOK = true
				k.Tracefs = p
			}
		}
	}
	if k.Tracefs == "" {
		k.Tracefs = "未挂载 tracefs"
	}

	_, rel, _ := uname()
	var cfgBytes []byte
	for _, p := range []string{"/boot/config-" + rel, "/lib/modules/" + rel + "/build/.config"} {
		if b, err := os.ReadFile(p); err == nil {
			k.ConfigFile = p
			cfgBytes = b
			break
		}
	}
	if cfgBytes == nil {
		if f, err := os.Open("/proc/config.gz"); err == nil {
			defer f.Close()
			if gz, err := gzip.NewReader(f); err == nil {
				if b, err := io.ReadAll(gz); err == nil {
					k.ConfigFile = "/proc/config.gz"
					cfgBytes = b
				}
			}
		}
	}
	if cfgBytes != nil {
		want := []string{
			"CONFIG_BPF_SYSCALL", "CONFIG_BPF_EVENTS", "CONFIG_BPF_JIT",
			"CONFIG_KPROBE_EVENTS", "CONFIG_KPROBES", "CONFIG_DEBUG_INFO_BTF",
			"CONFIG_DEBUG_FS", "CONFIG_FTRACE", "CONFIG_PERF_EVENTS",
			"CONFIG_CGROUPS", "CONFIG_NET_CLS_BPF", "CONFIG_NET_SCH_INGRESS",
		}
		for _, line := range strings.Split(string(cfgBytes), "\n") {
			for _, w := range want {
				if strings.HasPrefix(line, w+"=") {
					k.Config[w] = strings.TrimPrefix(line, w+"=")
				}
			}
		}
	} else {
		k.ConfigFile = "未找到内核配置"
	}

	for _, p := range []string{
		"/proc/sys/kernel/unprivileged_bpf_disabled",
		"/proc/sys/kernel/perf_event_paranoid",
		"/proc/sys/kernel/kptr_restrict",
	} {
		if v := readFirst(p); v != "" {
			k.Sysctl[filepath.Base(p)] = v
		}
	}
	k.Lockdown = readFirst("/sys/kernel/security/lockdown")
	if k.Lockdown == "" {
		k.Lockdown = "未启用"
	}

	for _, t := range []string{"bpftool", "nethogs", "ss", "iftop", "iptables", "nft", "docker"} {
		if p, err := exec.LookPath(t); err == nil {
			k.Tools[t] = p
		} else {
			k.Tools[t] = ""
		}
	}
	return k
}

func isVirtual(name string) bool {
	if name == "lo" {
		return true
	}
	for _, p := range []string{"docker", "veth", "br-", "virbr", "tun", "tap", "wg", "vnet"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func readUint(path string) uint64 {
	v, _ := strconv.ParseUint(readFirst(path), 10, 64)
	return v
}

func ifaceSnapshot() map[string][2]uint64 {
	m := map[string][2]uint64{}
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return m
	}
	for _, e := range ents {
		base := "/sys/class/net/" + e.Name() + "/statistics/"
		m[e.Name()] = [2]uint64{readUint(base + "rx_bytes"), readUint(base + "tx_bytes")}
	}
	return m
}

func collectNet() NetInfo {
	n := NetInfo{ConnByProto: map[string]int{}}

	before := ifaceSnapshot()
	time.Sleep(1000 * time.Millisecond)
	after := ifaceSnapshot()

	ents, _ := os.ReadDir("/sys/class/net")
	for _, e := range ents {
		name := e.Name()
		base := "/sys/class/net/" + name + "/"
		it := Iface{
			Name:    name,
			MAC:     readFirst(base + "address"),
			State:   readFirst(base + "operstate"),
			MTU:     readFirst(base + "mtu"),
			Speed:   readFirst(base + "speed"),
			Virtual: isVirtual(name),
		}
		if b, ok := after[name]; ok {
			it.RXBytes, it.TXBytes = b[0], b[1]
			if a, ok2 := before[name]; ok2 {
				if b[0] >= a[0] {
					it.RXRate = float64(b[0]-a[0]) / 1024.0
				}
				if b[1] >= a[1] {
					it.TXRate = float64(b[1]-a[1]) / 1024.0
				}
			}
		}
		n.Interfaces = append(n.Interfaces, it)
	}
	sort.Slice(n.Interfaces, func(i, j int) bool { return n.Interfaces[i].Name < n.Interfaces[j].Name })

	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) > 2 && f[1] == "00000000" {
				n.DefaultRtr = f[0]
				break
			}
		}
	}

	conns := readConnections()
	n.ConnTotal = len(conns)
	for _, c := range conns {
		n.ConnByProto[c.Proto]++
	}
	return n
}

type conn struct {
	Proto string
	Inode string
}

func readConnections() []conn {
	var out []conn
	for _, spec := range []struct{ file, proto string }{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	} {
		b, err := os.ReadFile(spec.file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(b), "\n")
		for _, line := range lines[1:] {
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			out = append(out, conn{Proto: spec.proto, Inode: f[9]})
		}
	}
	return out
}

func collectAttrib() AttribInfo {
	a := AttribInfo{}
	conns := readConnections()
	a.ConnTotal = len(conns)

	start := time.Now()
	inodeToPid := map[string]int{}
	ents, err := os.ReadDir("/proc")
	if err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			a.ProcCount++
			fdDir := "/proc/" + e.Name() + "/fd"
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				link, err := os.Readlink(fdDir + "/" + fd.Name())
				if err != nil || !strings.HasPrefix(link, "socket:[") {
					continue
				}
				a.SocketFDs++
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				if _, ok := inodeToPid[inode]; !ok {
					inodeToPid[inode] = pid
				}
			}
		}
	}
	a.ScanMs = float64(time.Since(start).Microseconds()) / 1000.0

	for _, c := range conns {
		if _, ok := inodeToPid[c.Inode]; ok {
			a.ConnMapped++
		}
	}
	if a.ConnTotal > 0 {
		a.Coverage = float64(a.ConnMapped) / float64(a.ConnTotal) * 100
	}
	if f, err := os.Open("/proc/1/fd"); err == nil {
		f.Close()
		a.CanReadProc1 = true
	}
	return a
}

func newBufReader(r io.Reader) *bufio.Reader { return bufio.NewReader(r) }

func collectDocker() DockerInfo {
	d := DockerInfo{}
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		d.SocketExists = true
	} else if _, err := os.Stat("/run/docker.sock"); err == nil {
		d.SocketExists = true
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}
	_ = client

	if d.SocketExists {
		if body, err := dockerGet("/version"); err == nil {
			var v struct {
				Version string `json:"Version"`
			}
			if json.Unmarshal(body, &v) == nil {
				d.APIOK = true
				d.Version = v.Version
			}
		} else {
			d.Error = err.Error()
		}
		if d.APIOK {
			if body, err := dockerGet("/containers/json"); err == nil {
				var list []struct {
					Names []string `json:"Names"`
					State string   `json:"State"`
				}
				if json.Unmarshal(body, &list) == nil {
					d.Containers = len(list)
					for _, c := range list {
						nm := strings.Join(c.Names, ",")
						d.Names = append(d.Names, strings.TrimPrefix(nm, "/")+" ("+c.State+")")
					}
				}
			}
		}
	}

	if ents, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), "veth") {
				d.VethCount++
			}
		}
	}
	return d
}

func dockerGet(path string) ([]byte, error) {
	conn, err := net.DialTimeout("unix", "/var/run/docker.sock", 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	req := "GET " + path + " HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(newBufReader(conn), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func collectRuntime() RuntimeInfo {
	rt := RuntimeInfo{
		EUID:  os.Geteuid(),
		UID:   os.Getuid(),
		GID:   os.Getgid(),
		GoVer: runtime.Version(),
		Env:   map[string]string{},
	}
	if u, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(u), "\n") {
			if strings.HasPrefix(line, "VmRSS:") {
				rt.RSS = strings.TrimSpace(strings.TrimPrefix(line, "VmRSS:"))
			}
		}
	}
	if exe, err := os.Executable(); err == nil {
		rt.Exe = exe
	}
	if out, err := exec.Command("id", "-un").Output(); err == nil {
		rt.User = strings.TrimSpace(string(out))
	}
	return rt
}

func judge(r *Report) []Verdict {
	var v []Verdict

	bpfLevel, bpfDetail := "fail", "eBPF 不可用"
	switch {
	case r.Kernel.BTFOK && r.Kernel.BPFOK && r.Kernel.KprobeOK:
		bpfLevel = "ok"
		bpfDetail = "BTF + bpf() + kprobe 全部可用，可做进程级字节记账"
	case r.Kernel.BPFOK && !r.Kernel.BTFOK:
		bpfLevel = "warn"
		bpfDetail = "bpf() 可用但缺少 BTF，需按内核版本预编译偏移（成本高）"
	case r.Kernel.BTFOK && !r.Kernel.BPFOK:
		bpfLevel = "fail"
		bpfDetail = "有 BTF 但 bpf() 不可用：" + r.Kernel.BPFSyscall
	}
	v = append(v, Verdict{"ebpf", "eBPF 进程级记账", bpfLevel, bpfDetail})

	cfgBPF := r.Kernel.Config["CONFIG_BPF_SYSCALL"]
	if cfgBPF == "" {
		v = append(v, Verdict{"kconfig", "内核配置可读", "warn", "未找到内核配置，无法交叉验证编译开关"})
	} else {
		lv := "ok"
		if cfgBPF != "y" {
			lv = "fail"
		}
		v = append(v, Verdict{"kconfig", "内核配置可读", lv, "CONFIG_BPF_SYSCALL=" + cfgBPF})
	}

	covLevel := "ok"
	if r.Attrib.Coverage < 90 {
		covLevel = "warn"
	}
	v = append(v, Verdict{"attrib", "连接→进程归因", covLevel,
		fmt.Sprintf("覆盖 %.0f%%（%d/%d），全量扫描 %d 进程耗时 %.1f ms",
			r.Attrib.Coverage, r.Attrib.ConnMapped, r.Attrib.ConnTotal, r.Attrib.ProcCount, r.Attrib.ScanMs)})

	if r.Runtime.EUID == 0 {
		v = append(v, Verdict{"perm", "运行权限", "ok", "以 root 运行，可读全系统 /proc"})
	} else {
		v = append(v, Verdict{"perm", "运行权限", "fail", fmt.Sprintf("euid=%d，非 root，无法跨进程归因", r.Runtime.EUID)})
	}

	if r.Docker.SocketExists && r.Docker.APIOK {
		v = append(v, Verdict{"docker", "容器归因", "ok",
			fmt.Sprintf("Docker %s，%d 个容器，%d 个 veth", r.Docker.Version, r.Docker.Containers, r.Docker.VethCount)})
	} else if r.Docker.SocketExists {
		v = append(v, Verdict{"docker", "容器归因", "warn", "Docker socket 存在但 API 不可用: " + r.Docker.Error})
	} else {
		v = append(v, Verdict{"docker", "容器归因", "warn", "未发现 Docker，容器维度将不可用"})
	}

	hasPhys := false
	for _, it := range r.Net.Interfaces {
		if !it.Virtual && it.State == "up" {
			hasPhys = true
		}
	}
	if hasPhys {
		v = append(v, Verdict{"iface", "网卡采集", "ok", fmt.Sprintf("检测到 %d 个网卡", len(r.Net.Interfaces))})
	} else {
		v = append(v, Verdict{"iface", "网卡采集", "warn", "未发现 up 状态的物理网卡"})
	}
	return v
}
