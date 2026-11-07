package main

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Container 是一个运行中的容器及其对应的宿主机 veth 网卡。
type Container struct {
	ID    string
	Name  string
	Image string
	State string
	PID   int
	Veth  string // 宿主机侧 veth 名；host 网络模式为空
	NetNS bool
}

type DockerIndex struct {
	mu      sync.RWMutex
	byID    map[string]*Container
	byVeth  map[string]*Container
	lastAt  time.Time
	ok      bool
	version string
}

func NewDockerIndex() *DockerIndex {
	return &DockerIndex{byID: map[string]*Container{}, byVeth: map[string]*Container{}}
}

func (d *DockerIndex) Get(id string) *Container {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.byID[id]
}

func (d *DockerIndex) ByVeth(name string) *Container {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.byVeth[name]
}

func (d *DockerIndex) List() []*Container {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*Container, 0, len(d.byID))
	for _, c := range d.byID {
		out = append(out, c)
	}
	return out
}

func (d *DockerIndex) Status() (bool, string, int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ok, d.version, len(d.byID)
}

// Refresh 拉一次容器列表，并为每个容器找到它在宿主机上的 veth。
// 思路：容器的 eth0 的 iflink 指向宿主机 veth 的 ifindex。
func (d *DockerIndex) Refresh() {
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		d.mu.Lock()
		d.ok = false
		d.mu.Unlock()
		return
	}

	body, err := dockerGet("/containers/json")
	if err != nil {
		d.mu.Lock()
		d.ok = false
		d.mu.Unlock()
		return
	}
	var list []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Image string   `json:"Image"`
		State string   `json:"State"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return
	}

	ifindexToName := hostIfindexMap()

	byID := make(map[string]*Container, len(list))
	byVeth := map[string]*Container{}

	for _, c := range list {
		ct := &Container{ID: c.ID, Image: c.Image, State: c.State}
		if len(c.Names) > 0 {
			ct.Name = strings.TrimPrefix(c.Names[0], "/")
		}
		if ct.Name == "" && len(c.ID) >= 12 {
			ct.Name = c.ID[:12]
		}
		if pid, netmode := inspectPid(c.ID); pid > 0 {
			ct.PID = pid
			ct.NetNS = netmode
			if ifidx := containerPeerIfindex(pid, ifindexToName); ifidx > 0 {
				if name, ok := ifindexToName[ifidx]; ok {
					ct.Veth = name
					byVeth[name] = ct
				}
			}
		}
		byID[c.ID] = ct
	}

	d.mu.Lock()
	d.byID = byID
	d.byVeth = byVeth
	d.lastAt = time.Now()
	d.ok = true
	d.mu.Unlock()
}

func hostIfindexMap() map[int]string {
	m := map[int]string{}
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return m
	}
	for _, e := range ents {
		b, err := os.ReadFile("/sys/class/net/" + e.Name() + "/ifindex")
		if err != nil {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
			m[v] = e.Name()
		}
	}
	return m
}

// containerPeerIfindex 找容器内某块网卡的 iflink，即宿主机侧 veth 的 ifindex。
// 不写死 eth0：容器可能改名，也可能有多块网卡；以「对得上宿主机网卡」为准。
func containerPeerIfindex(pid int, hostIf map[int]string) int {
	base := "/proc/" + strconv.Itoa(pid) + "/root/sys/class/net"
	ents, err := os.ReadDir(base)
	if err != nil {
		return 0
	}
	best := 0
	for _, e := range ents {
		b, err := os.ReadFile(base + "/" + e.Name() + "/iflink")
		if err != nil {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || v <= 0 {
			continue
		}
		if _, ok := hostIf[v]; !ok {
			continue
		}
		if e.Name() == "eth0" {
			return v // eth0 优先
		}
		if best == 0 {
			best = v
		}
	}
	return best
}

func inspectPid(id string) (int, bool) {
	body, err := dockerGet("/containers/" + id + "/json")
	if err != nil {
		return 0, false
	}
	var v struct {
		State struct {
			Pid int `json:"Pid"`
		} `json:"State"`
		HostConfig struct {
			NetworkMode string `json:"NetworkMode"`
		} `json:"HostConfig"`
	}
	if json.Unmarshal(body, &v) != nil {
		return 0, false
	}
	return v.State.Pid, v.HostConfig.NetworkMode == "host"
}

func dockerVersion() string {
	body, err := dockerGet("/version")
	if err != nil {
		return ""
	}
	var v struct {
		Version string `json:"Version"`
	}
	if json.Unmarshal(body, &v) != nil {
		return ""
	}
	return v.Version
}
