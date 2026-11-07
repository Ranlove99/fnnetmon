package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
	"time"
)

// 可执行文件签名。
//
// 用途：两个进程都叫 node，靠路径能区分；但「同一个路径的二进制被换掉了」
// 只有哈希能看出来。对 NAS 这种会长期不重启的机器，这条信息比想象中有用
// —— 突然有一天 /usr/local/bin/xxx 开始往外连，先看哈希变没变。
//
// 实现上刻意避开采集循环：哈希计算放后台 worker，Get 永远只读缓存。
// 一个 32MB 的二进制在 ARM 上算 sha256 要上百毫秒，塞进 1 秒一次的 tick
// 就是直接卡死采集。

type sigEntry struct {
	hash string
	size int64
	at   time.Time
}

type SigCache struct {
	mu      sync.Mutex
	m       map[string]*sigEntry
	pending map[string]bool
	q       chan string

	maxSize int64
	ttl     time.Duration
}

func NewSigCache() *SigCache {
	s := &SigCache{
		m:       map[string]*sigEntry{},
		pending: map[string]bool{},
		q:       make(chan string, 128),
		maxSize: 32 << 20, // 超过 32MB 不哈希，NAS 上大文件多半是数据不是程序
		ttl:     30 * time.Minute,
	}
	go s.worker()
	return s
}

// Get 返回缓存的短哈希（8 位十六进制）。缓存里没有就先排进队列，本次返回空。
func (s *SigCache) Get(path string) string {
	if path == "" || s == nil {
		return ""
	}
	s.mu.Lock()
	e := s.m[path]
	if e != nil && time.Since(e.at) < s.ttl {
		h := e.hash
		s.mu.Unlock()
		return h
	}
	if !s.pending[path] {
		s.pending[path] = true
		select {
		case s.q <- path:
		default: // 队列满就放弃这一条，下次再排，绝不阻塞调用方
			delete(s.pending, path)
		}
	}
	var h string
	if e != nil {
		h = e.hash
	}
	s.mu.Unlock()
	return h
}

func (s *SigCache) worker() {
	for path := range s.q {
		ent := s.compute(path)
		s.mu.Lock()
		s.m[path] = ent
		delete(s.pending, path)
		s.mu.Unlock()
	}
}

func (s *SigCache) compute(path string) *sigEntry {
	ent := &sigEntry{at: time.Now()}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return ent
	}
	ent.size = fi.Size()
	if fi.Size() > s.maxSize {
		return ent
	}
	f, err := os.Open(path)
	if err != nil {
		return ent
	}
	defer f.Close()
	h := sha256.New()
	// 只读这么多，防止文件在读取期间被写大
	if _, err := io.Copy(h, io.LimitReader(f, s.maxSize)); err != nil {
		return ent
	}
	ent.hash = hex.EncodeToString(h.Sum(nil))[:8]
	return ent
}

// 全局单例：进程内所有调用方共用一份缓存。
var exeSig = NewSigCache()
