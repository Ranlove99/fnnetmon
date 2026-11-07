package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type connKey struct {
	proto  string
	local  string
	remote string
}

// unattrName 是「找不到主人」的流量在历史库和界面上的统一名字。
const unattrName = "未归因"

type connPrev struct {
	tx, rx   uint64
	first    time.Time
	lastSeen time.Time
	proc     string
	exe      string
	cont     string
	pid      int
	state    string
	rtt      uint32
}

type ProcAgg struct {
	Key       string  `json:"key"`
	Name      string  `json:"name"`
	Service   string  `json:"svc,omitempty"` // 所属服务，前端按它分组；容器条目为空
	Exe       string  `json:"exe,omitempty"` // 可执行文件路径，用来区分同名的多个进程
	Container string  `json:"container"`
	Conns     int     `json:"conns"` // -1 表示未知（容器走 veth 统计，拿不到连接数）
	TxRate    float64 `json:"txr"`
	RxRate    float64 `json:"rxr"`
	Tx        uint64  `json:"tx"`
	Rx        uint64  `json:"rx"`
	Src       string  `json:"src"` // "conn" | "veth"
	Veth      string  `json:"veth,omitempty"`
	// Pseudo 标记「不是应用」的伪进程：无主 socket 和 TIME_WAIT 内核连接。
	// 它们有字节数但没有主人，前端会把它们折叠进「未归因」，不能当应用排在榜首。
	Pseudo string `json:"pseudo,omitempty"` // "unknown" | "closed"

	seen time.Time // 内部用：最近一次出现，用于清理僵尸条目
}

type ConnView struct {
	Proto     string `json:"proto"`
	State     string `json:"state"`
	Proc      string `json:"proc"`
	Exe       string `json:"exe"`
	Container string `json:"container"`
	// Svc 是用户认得出的应用名（应用目录 display_name > systemd 单元名）。
	// 连接页首屏拿它当主标题，进程名退到副行——系统资源管理器也是这么排的，
	// 用户按「飞牛影视」找，不按 trim_media 找。
	Svc     string  `json:"svc,omitempty"`
	PID     int     `json:"pid"`
	Local   string  `json:"local"`
	Remote  string  `json:"remote"`
	Scope   string  `json:"scope"` // loop | lan | wan
	Host    string  `json:"host"`
	Domain  string  `json:"domain,omitempty"`
	DomainN int     `json:"domain_n,omitempty"`
	CC      string  `json:"cc,omitempty"`
	CName   string  `json:"cname,omitempty"`
	City    string  `json:"city,omitempty"`
	Region  string  `json:"region,omitempty"`
	ASN     uint    `json:"asn,omitempty"`
	ASNOrg  string  `json:"asn_org,omitempty"`
	TxRate  float64 `json:"txr"`
	RxRate  float64 `json:"rxr"`
	Tx      uint64  `json:"tx"`
	Rx      uint64  `json:"rx"`
	RTT     float64 `json:"rtt"`
	Age     int64   `json:"age"`
}

type IfaceView struct {
	Name    string  `json:"name"`
	Up      bool    `json:"up"`
	Speed   string  `json:"speed"`
	Virtual bool    `json:"virtual"`
	TxRate  float64 `json:"txr"`
	RxRate  float64 `json:"rxr"`
	Tx      uint64  `json:"tx"`
	Rx      uint64  `json:"rx"`
}

type Snapshot struct {
	TS      string      `json:"ts"`
	Uptime  int64       `json:"uptime"`
	TxRate  float64     `json:"tx_rate"`
	RxRate  float64     `json:"rx_rate"`
	TxTotal uint64      `json:"tx_total"`
	RxTotal uint64      `json:"rx_total"`
	Ifaces  []IfaceView `json:"ifaces"`
	Conns   []ConnView  `json:"conns"`
	Procs   []ProcAgg   `json:"procs"`
	Conts   []ProcAgg   `json:"conts"`
	Meta    Meta        `json:"meta"`

	// 网卡总量和已归因量之间的账要算清楚。对不上就是有流量没找到主人
	// （UDP 没有字节计数、容器 netns、无主 socket、内核态），
	// 这时候界面上必须直说，而不是假装总量就等于各进程之和。
	LoopTxRate   float64 `json:"loop_tx"` // 本机回环，已去重，不计入网络流量
	LoopRxRate   float64 `json:"loop_rx"`
	AttrTxRate   float64 `json:"attr_tx"` // 已归因到具体进程/容器的部分
	AttrRxRate   float64 `json:"attr_rx"`
	UnattrTxRate float64 `json:"unattr_tx"` // 网卡总量 − 已归因
	UnattrRxRate float64 `json:"unattr_rx"`

	// UnattrParts 是「未归因」的拆解，来自 nftables 的只读计数表。
	// 拿不到时 Available=false，界面就只显示总数，不显示细分。
	UnattrParts UnattrParts `json:"unattr_parts"`
}

type Meta struct {
	ProcCount   int     `json:"procs"`
	SocketCount int     `json:"sockets"`
	ScanMs      float64 `json:"scan_ms"`
	ConnCount   int     `json:"conn_count"`
	Unknown     int     `json:"unknown"`
	Containers  int     `json:"containers"`
	VethMapped  int     `json:"veth_mapped"`
	DockerOK    bool    `json:"docker_ok"`
	DockerVer   string  `json:"docker_ver"`
	LoopConns   int     `json:"loop_conns"` // 本机回环连接数
	NoByte      int     `json:"nobyte"`     // 没有字节计数的 socket（UDP），它们的流量只能算进未归因
}

type Hub struct {
	mu       sync.RWMutex
	prev     map[connKey]*connPrev
	procTot  map[string]*ProcAgg
	contTot  map[string]*ProcAgg
	snap     *Snapshot
	started  time.Time
	proc     *ProcIndex
	docker   *DockerIndex
	svc      *ServiceIndex
	ifPrev   map[string][2]uint64
	resolver *Resolver

	store     *Store
	peer      *PeerTracker
	dom       *DomainCache
	geo       *GeoDB
	stat      *StatSampler
	accMu     sync.Mutex
	acc       map[string]*aggItem // dim|key → 本分钟累计
	curMinute int64

	// 采集健康度统计，给 /api/selfcheck 用
	tickN    int
	tickLast time.Duration
	tickMax  time.Duration
	tickSum  time.Duration
	tickAt   int64 // 最近一次 tick 的 unix 秒
}

// aggItem 是分钟桶里的累加单元。
type aggItem struct {
	dim string
	key string
	tx  int64
	rx  int64
}

func NewHub() *Hub {
	return &Hub{
		prev:     map[connKey]*connPrev{},
		procTot:  map[string]*ProcAgg{},
		contTot:  map[string]*ProcAgg{},
		started:  time.Now(),
		proc:     NewProcIndex(),
		docker:   NewDockerIndex(),
		svc:      NewServiceIndex(),
		ifPrev:   map[string][2]uint64{},
		resolver: NewResolver(),
		acc:      map[string]*aggItem{},
	}
}

// AttachStore 挂上历史库；挂上后每秒的增量会被累加进分钟桶。
func (h *Hub) AttachStore(s *Store) { h.store = s }

// AttachPeer 挂上外联追踪器。即使历史库不可用也要挂（它可以纯内存工作），
// 「有新程序联网了」这个提醒不该依赖数据库。
func (h *Hub) AttachPeer(t *PeerTracker) { h.peer = t }

// AttachEnrich 挂上域名和地理信息源，两者都可为 nil。
func (h *Hub) AttachEnrich(dom *DomainCache, geo *GeoDB) {
	h.dom = dom
	h.geo = geo
}

// AttachStat 挂上「未归因」拆解采样器。为 nil 时快照里就没有细分。
func (h *Hub) AttachStat(s *StatSampler) { h.stat = s }

func (h *Hub) Start() {
	h.proc.Scan()
	h.docker.Refresh()
	h.tick()

	go func() {
		ps := time.NewTicker(5 * time.Second)
		ds := time.NewTicker(30 * time.Second)
		ts := time.NewTicker(1 * time.Second)
		defer ps.Stop()
		defer ds.Stop()
		defer ts.Stop()
		for {
			select {
			case <-ps.C:
				h.proc.Scan()
			case <-ds.C:
				h.docker.Refresh()
				h.svc.Refresh()
				if h.peer != nil {
					h.peer.Flush()
				}
				if h.dom != nil {
					h.dom.Prune(time.Now().Unix())
				}
			case <-ts.C:
				h.tick()
			}
		}
	}()
}

func (h *Hub) Snapshot() *Snapshot {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.snap == nil {
		return &Snapshot{TS: time.Now().Format("15:04:05")}
	}
	return h.snap
}

func (h *Hub) tick() {
	t0 := time.Now()
	defer func() {
		d := time.Since(t0)
		h.mu.Lock()
		h.tickN++
		n := h.tickN
		h.tickLast = d
		h.tickSum += d
		if d > h.tickMax {
			h.tickMax = d
		}
		h.tickAt = time.Now().Unix()
		h.mu.Unlock()
		// 每 5 分钟清一次僵尸条目。procTot 只增不减的话，跑一个月会积累
		// 几千条再也用不到的记录——内存泄漏里最容易被忽略的一类。
		if n%300 == 0 {
			h.pruneTotals(time.Now())
		}
	}()

	now := time.Now()
	ifaces, totTx, totRx := h.sampleIfaces()
	socks, _ := DumpSockets()

	next := make(map[connKey]*connPrev, len(socks))
	connViews := make([]ConnView, 0, len(socks))
	procRate := map[string]*ProcAgg{}
	contRate := map[string]*ProcAgg{}
	unknown, loopConns, noByte := 0, 0, 0
	var loopTx, loopRx float64

	for _, s := range socks {
		key := connKey{s.Proto, s.LocalIP + ":" + strconv.Itoa(int(s.LocalPort)), s.RemoteIP + ":" + strconv.Itoa(int(s.RemotePort))}
		if s.RemoteIP == "0.0.0.0" || s.RemoteIP == "::" || s.State == tcpListen {
			continue // 监听态没有流量意义，跳过
		}

		var procName, exe, cont, cg, svcName, pseudo string
		var pid int
		var owned bool // 有明确进程归属才值得记「首次外联」，无主 socket 记了也没法生成规则
		if info := h.proc.Lookup(s.Inode); info != nil {
			owned = true
			procName, exe, pid, cg = info.Name, info.Exe, info.PID, info.Cgroup
			svcName = h.svc.Name(info)
			if info.ContainerID != "" {
				if c := h.docker.Get(info.ContainerID); c != nil {
					cont = c.Name
				} else if len(info.ContainerID) >= 12 {
					cont = info.ContainerID[:12]
				}
				// 容器内进程统一记到容器名下，否则一个容器会被拆成十几行
				svcName = ""
			}
		} else if s.State == tcpTimeWait || s.State == tcpClose {
			// TIME_WAIT 的内核 socket 本来就没有进程持有，单独归类，不算「无主」
			procName, pseudo = "已关闭连接", "closed"
		} else {
			procName, pseudo = "系统 / 无主 socket", "unknown"
			unknown++
		}

		// 回环连接在宿主机上有两个 socket（客户端和服务端各一个），
		// 字节数互为镜像：A 的发送量正是 B 的接收量。两端都记会让排行里
		// 出现两个合计完全相同、方向相反的行，数字还整体翻倍。
		// 只按固定的一端计数（本地端口大的那端），结果确定且不依赖遍历顺序。
		scope := peerScope(s.RemoteIP)
		countBytes := connCountsBytes(scope, s.LocalPort, s.RemotePort)
		if !s.HasBytes {
			// UDP 的 inet_diag 不返回字节计数，这些连接只能算「有连接、没流量」，
			// 它们的字节最终会落进「未归因」，必须在界面上说清楚。
			noByte++
		}

		var dTx, dRx float64
		fresh := false
		cur := &connPrev{tx: s.TxBytes, rx: s.RxBytes, proc: procName, exe: exe, cont: cont, pid: pid, state: tcpStateName(s.State), rtt: s.RTT}
		if old, ok := h.prev[key]; ok {
			cur.first = old.first
			if s.HasBytes && s.TxBytes >= old.tx {
				dTx = float64(s.TxBytes - old.tx)
			}
			if s.HasBytes && s.RxBytes >= old.rx {
				dRx = float64(s.RxBytes - old.rx)
			}
		} else {
			cur.first = now
			fresh = true
		}
		cur.lastSeen = now
		next[key] = cur

		// 首次外联观测：只记有进程归属、且不是 TIME_WAIT 的连接
		if h.peer != nil && owned && s.State != tcpTimeWait && s.State != tcpClose {
			h.peer.Observe(peerObs{
				Proc: procName, Cont: cont, Cgroup: cg, Path: exe, IP: s.RemoteIP,
				Port: int(s.RemotePort), Proto: s.Proto, Fresh: fresh,
				Tx: s.TxBytes, Rx: s.RxBytes,
			})
		}

		// 按「服务 + 进程」聚合。只按进程名会把不同应用的同名进程（一堆 node）
		// 混成一条，用户就没法判断是哪个应用在跑。
		pkey := procName
		if cont != "" {
			pkey = "container:" + cont
		} else if svcName != "" {
			pkey = svcName + "|" + procName
		}
		pa := procRate[pkey]
		if pa == nil {
			pa = &ProcAgg{Key: pkey, Name: procName, Service: svcName, Exe: exe, Container: cont, Pseudo: pseudo}
			procRate[pkey] = pa
		}
		pa.Conns++

		// 回环流量单独记账：它不是网络流量，混进排行只会把真正的答案挤下去。
		if scope == "loop" {
			loopConns++
			if countBytes {
				loopTx += dTx
				loopRx += dRx
			}
		} else if countBytes {
			pa.TxRate += dTx
			pa.RxRate += dRx
		}

		if cont != "" {
			ca := contRate[cont]
			if ca == nil {
				ca = &ProcAgg{Key: cont, Name: cont, Container: cont, Src: "conn"}
				contRate[cont] = ca
			}
			ca.Conns++
			if scope != "loop" && countBytes {
				ca.TxRate += dTx
				ca.RxRate += dRx
			}
		}

		// 域名优先于反查：104.16.x.x → cloudflare.com 比 → ec2-... 有用得多
		host := h.resolver.Lookup(s.RemoteIP)
		var domName string
		var domN int
		if h.dom != nil {
			if n, extra := h.dom.Lookup(s.RemoteIP, now.Unix()); n != "" {
				domName, domN = n, extra
				host = n
			}
		}
		var g GeoInfo
		if h.geo != nil && !isPrivateIP(s.RemoteIP) {
			g = h.geo.Lookup(s.RemoteIP)
		}

		connViews = append(connViews, ConnView{
			Proto: s.Proto, State: cur.state, Proc: procName, Exe: exe, Container: cont, Svc: svcName, PID: pid,
			Local:  s.LocalIP + ":" + strconv.Itoa(int(s.LocalPort)),
			Remote: s.RemoteIP + ":" + strconv.Itoa(int(s.RemotePort)),
			Scope:  scope,
			Host:   host,
			Domain: domName, DomainN: domN,
			CC: g.CC, CName: g.Name, City: g.City, Region: g.Region,
			ASN: g.ASN, ASNOrg: g.Org,
			TxRate: dTx, RxRate: dRx, Tx: s.TxBytes, Rx: s.RxBytes,
			RTT: float64(s.RTT) / 1000.0,
			Age: int64(now.Sub(cur.first).Seconds()),
		})
	}

	// 容器 socket 在独立 network namespace 里，宿主机 sock_diag 看不到，
	// 所以容器维度改用宿主机侧 veth 的字节统计——顺便把 UDP 也覆盖了。
	ifaceRate := make(map[string]IfaceView, len(ifaces))
	for _, it := range ifaces {
		ifaceRate[it.Name] = it
	}
	vethMapped := 0
	for _, c := range h.docker.List() {
		agg := contRate[c.Name]
		if agg == nil {
			agg = &ProcAgg{Key: c.Name, Name: c.Name, Container: c.Name, Conns: -1, Src: "veth"}
			contRate[c.Name] = agg
		}
		if c.Veth == "" {
			continue
		}
		it, ok := ifaceRate[c.Veth]
		if !ok {
			continue
		}
		vethMapped++
		agg.Veth = c.Veth
		// veth 在宿主机的 tx 是「进容器」，rx 是「出容器」，方向要翻过来
		agg.RxRate += it.TxRate
		agg.TxRate += it.RxRate
	}

	// 已归因 = 有主人的 socket + 容器 veth。伪进程（无主 socket、TIME_WAIT）
	// 不算在内：它们本来就要落进「未归因」那一栏，否则两边会重复计一次。
	var attrTx, attrRx float64
	for k, v := range procRate {
		if v.Pseudo != "" || strings.HasPrefix(k, "container:") {
			continue
		}
		attrTx += v.TxRate
		attrRx += v.RxRate
	}
	for _, v := range contRate {
		if v.Src == "veth" {
			attrTx += v.TxRate
			attrRx += v.RxRate
		}
	}
	unattrTx, unattrRx := totTx-attrTx, totRx-attrRx
	if unattrTx < 0 {
		unattrTx = 0
	}
	if unattrRx < 0 {
		unattrRx = 0
	}

	// 累计量
	h.mu.Lock()
	for k, v := range procRate {
		if tot, ok := h.procTot[k]; ok {
			tot.Tx += uint64(v.TxRate)
			tot.Rx += uint64(v.RxRate)
			tot.TxRate, tot.RxRate, tot.Conns = v.TxRate, v.RxRate, v.Conns
			tot.Name = v.Name
			tot.seen = now
		} else {
			v.seen = now
			h.procTot[k] = v
		}
	}
	for k, v := range contRate {
		if tot, ok := h.contTot[k]; ok {
			tot.Tx += uint64(v.TxRate)
			tot.Rx += uint64(v.RxRate)
			tot.TxRate, tot.RxRate, tot.Conns = v.TxRate, v.RxRate, v.Conns
			tot.seen = now
		} else {
			v.seen = now
			h.contTot[k] = v
		}
	}
	procs := make([]ProcAgg, 0, len(procRate))
	for _, v := range procRate {
		item := *v
		if t, ok := h.procTot[v.Key]; ok {
			item.Tx, item.Rx = t.Tx, t.Rx
		}
		procs = append(procs, item)
	}
	conts := make([]ProcAgg, 0, len(contRate))
	for _, v := range contRate {
		item := *v
		if t, ok := h.contTot[v.Key]; ok {
			item.Tx, item.Rx = t.Tx, t.Rx
		}
		conts = append(conts, item)
	}
	h.prev = next
	h.mu.Unlock()

	sort.Slice(procs, func(i, j int) bool { return procs[i].TxRate+procs[i].RxRate > procs[j].TxRate+procs[j].RxRate })
	sort.Slice(conts, func(i, j int) bool { return conts[i].TxRate+conts[i].RxRate > conts[j].TxRate+conts[j].RxRate })
	sort.Slice(connViews, func(i, j int) bool {
		return connViews[i].TxRate+connViews[i].RxRate > connViews[j].TxRate+connViews[j].RxRate
	})

	pc, sc, sd := h.proc.Stats()
	dok, dver, dcount := h.docker.Status()

	snap := &Snapshot{
		TS:     now.Format("15:04:05"),
		Uptime: int64(time.Since(h.started).Seconds()),
		TxRate: totTx,
		RxRate: totRx,
		Ifaces: ifaces,
		Conns:  connViews,
		Procs:  procs,
		Conts:  conts,
		Meta: Meta{
			ProcCount: pc, SocketCount: sc, ScanMs: float64(sd.Microseconds()) / 1000.0,
			ConnCount: len(connViews), Unknown: unknown,
			Containers: dcount, DockerOK: dok, DockerVer: dver, VethMapped: vethMapped,
			LoopConns: loopConns, NoByte: noByte,
		},
		LoopTxRate: loopTx, LoopRxRate: loopRx,
		AttrTxRate: attrTx, AttrRxRate: attrRx,
		UnattrTxRate: unattrTx, UnattrRxRate: unattrRx,
	}
	if h.stat != nil {
		snap.UnattrParts = h.stat.Snapshot()
	}
	for _, it := range ifaces {
		snap.TxTotal += it.Tx
		snap.RxTotal += it.Rx
	}

	h.mu.Lock()
	h.snap = snap
	h.mu.Unlock()

	h.accumulate(procs, conts, ifaces, totTx, totRx)
}

// ProcServices 返回「进程名 → 服务名」的当前映射。
// 历史库是按进程名存 key 的，查历史排行时要靠它把进程归并回服务。
// 已经退出、不在当前快照里的进程查不到，归并时按它自己算，这是可接受的近似。
func (h *Hub) ProcServices() map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make(map[string]string, len(h.procTot))
	for _, v := range h.procTot {
		if v.Service != "" && v.Name != "" {
			out[v.Name] = v.Service
		}
	}
	return out
}

// ServiceStatus 给自检用：应用目录有没有找到、认出了几个应用。
func (h *Hub) ServiceStatus() (string, int) {
	if h.svc == nil {
		return "", 0
	}
	return h.svc.Status()
}

// pruneTotals 删掉长时间没出现过的进程/容器累计条目。
// TTL 取 6 小时而不是 1 小时：cron 类的定时任务可能隔几小时才出现一次，
// 太短的 TTL 会让它们的累计流量反复清零。
func (h *Hub) pruneTotals(now time.Time) {
	const ttl = 6 * time.Hour
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, v := range h.procTot {
		if !v.seen.IsZero() && now.Sub(v.seen) > ttl {
			delete(h.procTot, k)
		}
	}
	for k, v := range h.contTot {
		if !v.seen.IsZero() && now.Sub(v.seen) > ttl {
			delete(h.contTot, k)
		}
	}
}

// accumulate 把本秒的增量累加进当前分钟桶，跨分钟时落盘。
func (h *Hub) accumulate(procs, conts []ProcAgg, ifaces []IfaceView, totTx, totRx float64) {
	if h.store == nil {
		return
	}
	h.accMu.Lock()
	defer h.accMu.Unlock()

	// 先处理跨分钟，再累加本秒，否则跨分钟那一秒的数据会被算进上一分钟。
	min := alignBucket(time.Now().Unix(), 60)
	if h.curMinute != 0 && min != h.curMinute {
		h.flushLocked()
	}
	h.curMinute = min

	add := func(dim, key string, tx, rx float64) {
		if tx <= 0 && rx <= 0 {
			return
		}
		k := dim + "\x00" + key
		it := h.acc[k]
		if it == nil {
			it = &aggItem{dim: dim, key: key}
			h.acc[k] = it
		}
		it.tx += int64(tx)
		it.rx += int64(rx)
	}

	for _, p := range procs {
		// 无主 socket 和 TIME_WAIT 不是应用，历史里统一记到「未归因」，
		// 否则「系统 / 无主 socket」会在历史排行里冒充一个应用。
		name := p.Name
		if p.Pseudo != "" {
			name = unattrName
		}
		add("proc", name, p.TxRate, p.RxRate)
	}
	for _, c := range conts {
		add("cont", c.Name, c.TxRate, c.RxRate)
	}
	for _, it := range ifaces {
		if it.Virtual || !it.Up {
			continue
		}
		add("iface", it.Name, it.TxRate, it.RxRate)
	}
	add("total", "all", totTx, totRx)
}

// flushLocked 把累积的分钟桶写库，调用方必须持有 accMu。
func (h *Hub) flushLocked() {
	if h.store == nil || len(h.acc) == 0 {
		return
	}
	rows := make([]AggRow, 0, len(h.acc))
	for _, it := range h.acc {
		rows = append(rows, AggRow{Bucket: h.curMinute, Gran: "1m", Dim: it.dim, Key: it.key, Tx: it.tx, Rx: it.rx})
	}
	if err := h.store.Flush(rows); err != nil {
		fmt.Fprintf(os.Stderr, "[fnnetmon] flush failed: %v\n", err)
	}
	h.acc = map[string]*aggItem{}
}

// FlushNow 立即落盘当前未写出的分钟桶，进程退出前调用。
func (h *Hub) FlushNow() {
	h.accMu.Lock()
	defer h.accMu.Unlock()
	h.flushLocked()
}

// sampleIfaces 只统计非虚拟、处于 up 状态的网卡作为「总流量」，
// 避免 docker0/veth/br-* 与物理网卡重复计数。
func (h *Hub) sampleIfaces() ([]IfaceView, float64, float64) {
	now := map[string][2]uint64{}
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil, 0, 0
	}
	out := make([]IfaceView, 0, len(ents))
	var totTx, totRx float64
	for _, e := range ents {
		name := e.Name()
		base := "/sys/class/net/" + name + "/"
		rx := readUint(base + "statistics/rx_bytes")
		tx := readUint(base + "statistics/tx_bytes")
		now[name] = [2]uint64{rx, tx}

		v := IfaceView{
			Name:    name,
			Up:      readFirst(base+"operstate") == "up",
			Speed:   readFirst(base + "speed"),
			Virtual: isVirtualIface(name),
			Tx:      tx, Rx: rx,
		}
		if old, ok := h.ifPrev[name]; ok {
			if tx >= old[1] {
				v.TxRate = float64(tx - old[1])
			}
			if rx >= old[0] {
				v.RxRate = float64(rx - old[0])
			}
		}
		out = append(out, v)
		if !v.Virtual && v.Up {
			totTx += v.TxRate
			totRx += v.RxRate
		}
	}
	h.mu.Lock()
	h.ifPrev = now
	h.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Virtual != out[j].Virtual {
			return !out[i].Virtual
		}
		return out[i].Name < out[j].Name
	})
	return out, totTx, totRx
}

// isVirtualIface 用 /sys/class/net/<if>/device 是否存在判断物理网卡。
// 不能只靠名字前缀：这台机器上的 NodeBabyLink（MTU 1430 的隧道）就不符合任何前缀。
func isVirtualIface(name string) bool {
	if name == "lo" {
		return true
	}
	if _, err := os.Stat("/sys/class/net/" + name + "/device"); err == nil {
		return false
	}
	return true
}

// Resolver 做异步反查，避免阻塞采样循环。
type Resolver struct {
	mu      sync.RWMutex
	cache   map[string]string
	pending map[string]bool
	sem     chan struct{}
}

const maxResolveCache = 4096

func NewResolver() *Resolver {
	return &Resolver{
		cache:   map[string]string{},
		pending: map[string]bool{},
		sem:     make(chan struct{}, 8),
	}
}

func (r *Resolver) Lookup(ip string) string {
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return ""
	}
	r.mu.RLock()
	name, ok := r.cache[ip]
	pend := r.pending[ip]
	r.mu.RUnlock()
	if ok {
		return name
	}
	if !pend && isPrivateIP(ip) {
		r.mu.Lock()
		r.pending[ip] = true
		r.mu.Unlock()
		go func() {
			r.sem <- struct{}{}
			defer func() { <-r.sem }()
			names, err := net.LookupAddr(ip)
			res := ""
			if err == nil && len(names) > 0 {
				res = strings.TrimSuffix(names[0], ".")
			}
			r.mu.Lock()
			// 反查缓存也得有上限。内网 IP 数量理论上可达上千（DHCP 池），
			// 而 DNS 反查结果重建成本很低，超了直接清空比做 LRU 划算。
			if len(r.cache) > maxResolveCache {
				r.cache = map[string]string{}
			}
			r.cache[ip] = res
			delete(r.pending, ip)
			r.mu.Unlock()
		}()
	}
	return ""
}

func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}

// peerScope 判断对端的性质。回环必须单独拎出来：本机两个进程互相传数据
// 既不经过网卡，也会在 sock_diag 里出现两次，混进排行只会制造假象。
func peerScope(remoteIP string) string {
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return "wan"
	}
	if ip.IsLoopback() {
		return "loop"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "lan"
	}
	return "wan"
}

// connCountsBytes 决定一条 socket 要不要把字节记进统计。
// 回环连接在宿主机上有两个 socket（客户端和服务端各一个），字节互为镜像：
// A 的发送量正是 B 的接收量。两端都记会让排行里出现两个合计完全相同、
// 方向相反的行，整体数字还翻倍。按本地端口较大的那一端记账——结果唯一、
// 与遍历顺序无关，也不会漏掉。
func connCountsBytes(scope string, localPort, remotePort uint16) bool {
	if scope != "loop" {
		return true
	}
	return localPort > remotePort
}

// Debug 输出容器映射的中间状态，方便在真机上排查「为什么容器归因不对」。
func (h *Hub) Debug() map[string]any {
	pc, sc, sd := h.proc.Stats()
	dok, dver, _ := h.docker.Status()
	conts := h.docker.List()
	out := make([]map[string]any, 0, len(conts))
	for _, c := range conts {
		item := map[string]any{
			"id": c.ID, "name": c.Name, "pid": c.PID, "veth": c.Veth,
			"state": c.State, "host_net": c.NetNS,
		}
		if c.PID > 0 {
			item["cgroup"] = readCgroupFirstLine(c.PID)
			item["peer_ifindex"] = containerPeerIfindex(c.PID, hostIfindexMap())
		}
		out = append(out, item)
	}
	root, apps := h.ServiceStatus()
	capps, cat, cerr := h.svc.CenterStatus()
	return map[string]any{
		"proc_count": pc, "socket_fds": sc,
		"scan_ms":   float64(sd.Microseconds()) / 1000.0,
		"docker_ok": dok, "docker_version": dver,
		"containers":   out,
		"service_root": root, "service_apps": apps,
		// appcenter-cli 这条来源单独报：它给的是应用中心维护的权威名字，
		// 读不到时服务名会退到 manifest，再退到包名——界面上就成了 trim.xxx。
		"service_center_apps": capps,
		"service_center_at":   cat.Format("15:04:05"),
		"service_center_err":  cerr,
		"note":                "容器 socket 在独立 netns，sock_diag 看不到；容器流量走 veth 统计",
	}
}

func readCgroupFirstLine(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return ""
	}
	line := strings.SplitN(string(b), "\n", 2)[0]
	return line
}
