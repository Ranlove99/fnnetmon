package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Peer 是「某个程序 ↔ 某个远端地址」的见面记录。
// Little Snitch 的核心体验就是这一条：这个程序第一次要连这个地址，你允许吗？
//
// 主键是 (proc, ip)：同一程序连同一台主机的不同端口算同一条对端，
// 否则一个浏览器开十个标签页就会刷出十条「新外联」，完全没法用。
type Peer struct {
	Proc    string `json:"proc"`
	Cont    string `json:"cont"`
	Cgroup  string `json:"cg"`
	Path    string `json:"path,omitempty"` // 可执行文件路径，区分同名进程
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	First   int64  `json:"first"`
	Last    int64  `json:"last"`
	Hits    int64  `json:"hits"`
	Tx      int64  `json:"tx"`
	Rx      int64  `json:"rx"`
	Verdict string `json:"verdict"` // "" 未裁决 | allow | deny
	Private bool   `json:"private"`
	Fresh   bool   `json:"fresh"` // 本次进程启动后才第一次出现

	// 以下字段不落库，每次查询时现算：域名会过期，哈希要读文件
	Hash    string `json:"hash,omitempty"`
	Domain  string `json:"domain,omitempty"`
	DomainN int    `json:"domain_n,omitempty"` // 该 IP 上还见过几个别的域名
	CC      string `json:"cc,omitempty"`
	CName   string `json:"cname,omitempty"`
	Region  string `json:"region,omitempty"` // 一级行政区，只有 City 库才有
	City    string `json:"city,omitempty"`
	ASN     uint   `json:"asn,omitempty"`
	ASNOrg  string `json:"asn_org,omitempty"`
	// Svc 是应用展示名，接口层用 Hub.ProcServices() 现查现填。
	// 用户按「飞牛影视」认外联，不按 trim_media；查不到（进程最近没流量）就空着，
	// 前端退回显示进程名。
	Svc string `json:"svc,omitempty"`
}

type peerKey struct{ proc, ip string }

// peerObs 是一次观测。用结构体而不是位置参数：
// 这里已经有 10 个字段，位置传参只要顺序错一个就是线上事故。
type peerObs struct {
	Proc   string
	Cont   string
	Cgroup string
	Path   string
	IP     string
	Port   int
	Proto  string
	Fresh  bool // 新建连接（不是同一连接的后续采样）
	Tx     uint64
	Rx     uint64
}

// PeerTracker 在内存里维护「见过哪些对端」，定期批量落库。
//
// 为什么不在 Observe 里直接写库：SQLite 的 busy_timeout 是 5 秒，
// 一旦撞上写锁就会把 1 秒一次的采集 tick 卡死。所有 IO 都推到 Flush 里做。
type PeerTracker struct {
	mu      sync.RWMutex
	items   map[peerKey]*Peer
	dirty   map[peerKey]bool
	store   *Store
	dom     *DomainCache
	geo     *GeoDB
	onNew   func(Peer)
	bootAt  int64
	lastRun time.Time
	maxKeep int
}

func NewPeerTracker(store *Store) *PeerTracker {
	t := &PeerTracker{
		items:   map[peerKey]*Peer{},
		dirty:   map[peerKey]bool{},
		store:   store,
		bootAt:  time.Now().Unix(),
		lastRun: time.Now(),
		maxKeep: 20000,
	}
	t.load()
	return t
}

// AttachEnrich 挂上域名和地理信息源。两个都可以是 nil（数据缺失时静默降级）。
func (t *PeerTracker) AttachEnrich(dom *DomainCache, geo *GeoDB) {
	t.dom, t.geo = dom, geo
}

// OnNew 注册「发现新外联」的回调。回调在锁外执行，可以放心做日志之类的慢操作。
func (t *PeerTracker) OnNew(fn func(Peer)) { t.onNew = fn }

// load 把历史对端读进内存，避免重启后所有对端都变成「新的」。
func (t *PeerTracker) load() {
	if t.store == nil {
		return
	}
	rows, err := t.store.db.Query(`
SELECT proc, ip, cont, cg, path, port, proto, first, last, hits, tx, rx, verdict
FROM peer ORDER BY first DESC LIMIT ?`, t.maxKeep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[fnnetmon] peer load failed: %v\n", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var p Peer
		if err := rows.Scan(&p.Proc, &p.IP, &p.Cont, &p.Cgroup, &p.Path, &p.Port, &p.Proto,
			&p.First, &p.Last, &p.Hits, &p.Tx, &p.Rx, &p.Verdict); err != nil {
			continue
		}
		p.Private = isPrivateIP(p.IP)
		t.items[peerKey{p.Proc, p.IP}] = &p
	}
}

// Observe 记录一次观测。
//
// fresh 表示这是一条新建的连接（而不是同一连接的后续采样），
// 只有它才让 hits 加一，否则 hits 会等于「活跃秒数」，没有意义。
func (t *PeerTracker) Observe(o peerObs) {
	if o.IP == "" || o.IP == "0.0.0.0" || o.IP == "::" || o.IP == "127.0.0.1" || o.IP == "::1" {
		return
	}
	k := peerKey{o.Proc, o.IP}
	now := time.Now().Unix()

	var born *Peer
	t.mu.Lock()
	p := t.items[k]
	if p == nil {
		p = &Peer{
			Proc: o.Proc, Cont: o.Cont, Cgroup: o.Cgroup, Path: o.Path,
			IP: o.IP, Port: o.Port, Proto: o.Proto,
			First: now, Last: now, Private: isPrivateIP(o.IP), Fresh: true,
		}
		t.items[k] = p
		if !p.Private {
			c := *p
			born = &c
		}
	}
	p.Last = now
	p.Tx, p.Rx = int64(o.Tx), int64(o.Rx)
	if o.Cont != "" {
		p.Cont = o.Cont
	}
	if o.Cgroup != "" {
		p.Cgroup = o.Cgroup
	}
	if o.Path != "" {
		p.Path = o.Path
	}
	if o.Fresh {
		p.Hits++
	}
	t.dirty[k] = true
	t.mu.Unlock()

	// 回调放在锁外：它可能要写日志，甚至做一次域名反查
	if born != nil && t.onNew != nil {
		t.onNew(*born)
	}
}

// Flush 把内存里变更过的对端批量写库。由 Hub 每 30 秒调用一次。
func (t *PeerTracker) Flush() {
	t.mu.Lock()
	if len(t.dirty) == 0 {
		t.mu.Unlock()
		return
	}
	rows := make([]Peer, 0, len(t.dirty))
	for k := range t.dirty {
		if p := t.items[k]; p != nil {
			rows = append(rows, *p)
		}
	}
	t.dirty = map[peerKey]bool{}
	t.evictLocked()
	t.lastRun = time.Now()
	t.mu.Unlock()

	if t.store == nil {
		return
	}
	// verdict 故意不覆盖：那是用户的裁决，不能被采集循环冲掉
	if err := t.store.UpsertPeers(rows); err != nil {
		fmt.Fprintf(os.Stderr, "[fnnetmon] peer flush failed: %v\n", err)
	}
}

// evictLocked 在超出上限时按「最近活动」淘汰。
//
// 这里原来是按 First（首次见到时间）淘汰，是个真实的缺陷：
// 一个三天前首次见到、现在每分钟都在通信的服务端，会比一小时前才见到的
// 一次性扫描器先被扔掉 —— 恰恰把最有价值的长连接记录丢了。改成按 Last。
func (t *PeerTracker) evictLocked() {
	if len(t.items) <= t.maxKeep {
		return
	}
	all := make([]*Peer, 0, len(t.items))
	for _, p := range t.items {
		all = append(all, p)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Last > all[j].Last })
	for i := t.maxKeep; i < len(all); i++ {
		delete(t.items, peerKey{all[i].Proc, all[i].IP})
	}
}

// Get 取单条对端的快照。
func (t *PeerTracker) Get(proc, ip string) *Peer {
	t.mu.RLock()
	var c *Peer
	if p := t.items[peerKey{proc, ip}]; p != nil {
		v := *p
		c = &v
	}
	t.mu.RUnlock()
	if c != nil {
		t.enrich(c)
	}
	return c
}

// enrich 补上不落库的展示字段。
func (t *PeerTracker) enrich(p *Peer) {
	now := time.Now().Unix()
	if t.dom != nil {
		p.Domain, p.DomainN = t.dom.Lookup(p.IP, now)
	}
	if t.geo != nil && !p.Private {
		g := t.geo.Lookup(p.IP)
		p.CC, p.CName, p.Region, p.City = g.CC, g.Name, g.Region, g.City
		p.ASN, p.ASNOrg = g.ASN, g.Org
	}
	if p.Path != "" {
		p.Hash = exeSig.Get(p.Path)
	}
}

// SetVerdict 记录用户对某个对端的裁决。
func (t *PeerTracker) SetVerdict(proc, ip, verdict string) error {
	t.mu.Lock()
	if p := t.items[peerKey{proc, ip}]; p != nil {
		p.Verdict = verdict
	}
	t.mu.Unlock()
	if t.store == nil {
		return nil
	}
	return t.store.SetPeerVerdict(proc, ip, verdict)
}

// List 返回对端列表，最新的在前。
func (t *PeerTracker) List(includePrivate, onlyPending bool, q string, limit int) []Peer {
	t.mu.RLock()
	out := make([]Peer, 0, len(t.items))
	for _, p := range t.items {
		if !includePrivate && p.Private {
			continue
		}
		if onlyPending && p.Verdict != "" {
			continue
		}
		out = append(out, *p)
	}
	t.mu.RUnlock()

	// 补全放在锁外：域名/地理补全可能触发文件读取，不该占着读锁。
	// 搜索也必须等补全之后再做，否则「按域名搜」会被提前过滤掉。
	for i := range out {
		t.enrich(&out[i])
	}
	if q != "" {
		filtered := out[:0]
		for i := range out {
			if peerMatch(&out[i], q) {
				filtered = append(filtered, out[i])
			}
		}
		out = filtered
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].First != out[j].First {
			return out[i].First > out[j].First
		}
		return out[i].Proc < out[j].Proc
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func peerMatch(p *Peer, q string) bool {
	lq := strings.ToLower(q)
	for _, f := range []string{p.Proc, p.Cont, p.IP, p.Cgroup, p.Domain, p.Path, p.ASNOrg, p.CName} {
		if f != "" && strings.Contains(strings.ToLower(f), lq) {
			return true
		}
	}
	return false
}

// Pending 返回「公网 + 还没裁决」的数量，用于顶栏角标。
func (t *PeerTracker) Pending() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, p := range t.items {
		if p.Verdict == "" && !p.Private {
			n++
		}
	}
	return n
}

func (t *PeerTracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.items)
}

// ---- 存储层 ----

func (s *Store) UpsertPeers(rows []Peer) error {
	if len(rows) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
INSERT INTO peer(proc,ip,cont,cg,path,port,proto,first,last,hits,tx,rx,verdict)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(proc,ip) DO UPDATE SET
  cont=excluded.cont, cg=excluded.cg, path=excluded.path, port=excluded.port, proto=excluded.proto,
  last=excluded.last, hits=excluded.hits, tx=excluded.tx, rx=excluded.rx`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Proc, r.IP, r.Cont, r.Cgroup, r.Path, r.Port, r.Proto,
			r.First, r.Last, r.Hits, r.Tx, r.Rx, r.Verdict); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetPeerVerdict(proc, ip, verdict string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE peer SET verdict=? WHERE proc=? AND ip=?`, verdict, proc, ip)
	return err
}

// DeletePeer 删除一条对端记录（用户点「忽略」时用）。
func (s *Store) DeletePeer(proc, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM peer WHERE proc=? AND ip=?`, proc, ip)
	return err
}

// ForgetPeer 让某个对端「重新变回陌生」，下次再连会被当成新外联。
func (t *PeerTracker) Forget(proc, ip string) error {
	t.mu.Lock()
	delete(t.items, peerKey{proc, ip})
	t.mu.Unlock()
	if t.store == nil {
		return nil
	}
	return t.store.DeletePeer(proc, ip)
}
