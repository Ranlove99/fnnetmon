package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcInfo 是一个进程的身份信息，用于把 socket 归因到「谁在用网」。
type ProcInfo struct {
	PID         int
	Name        string // comm，展示用
	Exe         string // 可执行文件路径
	Cmdline     string // 截断后的命令行
	ContainerID string // 从 cgroup 解析出的容器 ID，空表示宿主机进程
	Cgroup      string // cgroup v2 路径，如 /system.slice/trim-xxx.service（规则匹配用）
}

// ProcIndex 维护 inode → 进程 的映射。
// 全量扫描 512 个进程约 60ms（实测），5 秒一次对 6 核设备完全可接受。
type ProcIndex struct {
	mu       sync.RWMutex
	inodePID map[string]int
	procs    map[int]*ProcInfo
	lastScan time.Time
	scanDur  time.Duration
}

func NewProcIndex() *ProcIndex {
	return &ProcIndex{
		inodePID: map[string]int{},
		procs:    map[int]*ProcInfo{},
	}
}

func (p *ProcIndex) Scan() {
	start := time.Now()
	inodePID := make(map[string]int, 2048)
	procs := make(map[int]*ProcInfo, 600)

	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := "/proc/" + e.Name() + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var info *ProcInfo
		for _, fd := range fds {
			link, err := os.Readlink(fdDir + "/" + fd.Name())
			if err != nil || len(link) < 9 || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := link[8 : len(link)-1]
			if _, ok := inodePID[inode]; ok {
				continue
			}
			inodePID[inode] = pid
			if info == nil {
				info = readProcInfo(pid)
			}
		}
		if info != nil {
			procs[pid] = info
		}
	}

	p.mu.Lock()
	p.inodePID = inodePID
	p.procs = procs
	p.lastScan = time.Now()
	p.scanDur = time.Since(start)
	p.mu.Unlock()
}

func (p *ProcIndex) Lookup(inode uint32) *ProcInfo {
	key := strconv.FormatUint(uint64(inode), 10)
	p.mu.RLock()
	pid, ok := p.inodePID[key]
	var info *ProcInfo
	if ok {
		info = p.procs[pid]
	}
	p.mu.RUnlock()
	return info
}

func (p *ProcIndex) Stats() (int, int, time.Duration) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.procs), len(p.inodePID), p.scanDur
}

func readProcInfo(pid int) *ProcInfo {
	base := "/proc/" + strconv.Itoa(pid)
	info := &ProcInfo{PID: pid}

	if b, err := os.ReadFile(base + "/comm"); err == nil {
		info.Name = strings.TrimSpace(string(b))
	}
	if exe, err := os.Readlink(base + "/exe"); err == nil {
		info.Exe = exe
		// exe 带 " (deleted)" 后缀时剥掉
		info.Exe = strings.TrimSuffix(info.Exe, " (deleted)")
	}
	if b, err := os.ReadFile(base + "/cmdline"); err == nil && len(b) > 0 {
		parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		cl := strings.Join(parts, " ")
		if len(cl) > 160 {
			cl = cl[:160] + "…"
		}
		info.Cmdline = cl
	}
	if info.Name == "" && info.Exe != "" {
		info.Name = filepath.Base(info.Exe)
	}
	// 一次读文件，两个用途：容器 ID 和 cgroup 路径
	cg := readCgroup(pid)
	info.Cgroup = cg
	info.ContainerID = parseContainerID(cg)
	return info
}

// readCgroup 取 cgroup v2 路径。形如：
//
//	0::/system.slice/docker-<64hex>.scope
//
// 返回 "/system.slice/docker-<64hex>.scope"。
func readCgroup(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if i := strings.Index(s, "::"); i >= 0 {
		return strings.TrimSpace(s[i+2:])
	}
	return ""
}

// containerIDFromCgroup 从 /proc/pid/cgroup 里抠出 docker 容器 ID。
func containerIDFromCgroup(pid int) string {
	return parseContainerID(readCgroup(pid))
}

func parseContainerID(cg string) string {
	if cg == "" {
		return ""
	}
	for _, marker := range []string{"docker-", "/docker/"} {
		idx := strings.Index(cg, marker)
		if idx < 0 {
			continue
		}
		rest := cg[idx+len(marker):]
		id := make([]byte, 0, 64)
		for i := 0; i < len(rest) && i < 64; i++ {
			c := rest[i]
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
				id = append(id, c)
			} else {
				break
			}
		}
		if len(id) >= 12 {
			return string(id)
		}
	}
	return ""
}
