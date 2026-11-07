package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// 流量告警。
//
// 「谁在偷跑」的下一步是「偷跑的时候告诉我」——没人会一直盯着页面。
// 告警配置单独存 alerts.json，不塞 SQLite：数据库坏掉时告警设置还在，
// 和历史库解耦；和 firewall.json 一个思路。
//
// 设计上的克制：
//   - 只做「阈值 + 冷却」，不做规则引擎。复杂规则没人配得对。
//   - 评估在内存里做，30 秒一轮，绝不在采集循环里跑 IO。
//   - Webhook 失败只记日志 + 记一次失败次数，不重试轰炸对方。
//   - 推送格式按 URL 域名自动判断（企业微信 / 钉钉 / Slack / 通用），
//     用户不用记三种 JSON 结构。

type AlertRule struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`         // 显示名，留空就用 Match
	Match       string  `json:"match"`        // 服务名 / 进程名 / 容器名，留空表示所有
	Kind        string  `json:"kind"`         // rate（速率）| total（窗口内累计）
	Threshold   float64 `json:"threshold"`    // rate: KB/s；total: MB
	WindowMin   int     `json:"window_min"`   // total 用，默认 60
	CooldownMin int     `json:"cooldown_min"` // 触发后的静默期，默认 30
}

type AlertConfig struct {
	Enabled bool        `json:"enabled"`
	Webhook string      `json:"webhook"`
	Rules   []AlertRule `json:"rules"`
	// 以下为只读输出，不参与保存
	Events   []AlertEvent `json:"events,omitempty"`
	LastErr  string       `json:"last_err,omitempty"`
	LastSent string       `json:"last_sent,omitempty"`
}

type AlertEvent struct {
	At    int64   `json:"at"`
	Rule  string  `json:"rule"`
	Match string  `json:"match"`
	Value float64 `json:"value"`
	Unit  string  `json:"unit"`
	Text  string  `json:"text"`
	Sent  bool    `json:"sent"`
	Err   string  `json:"err,omitempty"`
}

type AlertEngine struct {
	mu       sync.Mutex
	cfg      AlertConfig
	path     string
	lastFire map[int64]time.Time // rule id → 上次触发
	winStart map[int64]time.Time // rule id → 当前窗口起点
	winBytes map[int64]float64   // rule id → 窗口内累计字节
	events   []AlertEvent        // 最近 50 条，内存环形
	client   *http.Client
}

const alertEventKeep = 50

func NewAlertEngine(path string) *AlertEngine {
	e := &AlertEngine{
		path:     path,
		lastFire: map[int64]time.Time{},
		winStart: map[int64]time.Time{},
		winBytes: map[int64]float64{},
		client:   &http.Client{Timeout: 10 * time.Second},
	}
	e.load()
	return e
}

func (e *AlertEngine) load() {
	b, err := os.ReadFile(e.path)
	if err != nil {
		return
	}
	var c AlertConfig
	if json.Unmarshal(b, &c) != nil {
		return
	}
	e.cfg = c
}

func (e *AlertEngine) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(e.path), 0o755); err != nil {
		return err
	}
	c := e.cfg
	c.Events = nil // 事件不进配置文件
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := e.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, e.path)
}

// Config 返回给界面用的副本（含最近事件）。
func (e *AlertEngine) Config() AlertConfig {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.cfg
	c.Events = append([]AlertEvent{}, e.events...)
	return c
}

// Save 保存配置。规则 ID 由服务端分配，前端不需要管。
func (e *AlertEngine) Save(in AlertConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	next := int64(1)
	for _, r := range in.Rules {
		if r.ID >= next {
			next = r.ID + 1
		}
	}
	for i := range in.Rules {
		if in.Rules[i].ID == 0 {
			in.Rules[i].ID = next
			next++
		}
		if in.Rules[i].Kind == "" {
			in.Rules[i].Kind = "rate"
		}
		if in.Rules[i].WindowMin <= 0 {
			in.Rules[i].WindowMin = 60
		}
		if in.Rules[i].CooldownMin <= 0 {
			in.Rules[i].CooldownMin = 30
		}
	}
	in.Enabled = in.Enabled && strings.TrimSpace(in.Webhook) != ""
	e.cfg = in
	e.cfg.Events = nil
	return e.saveLocked()
}

// Test 发一条测试消息，把错误直接回给界面——配错 URL 要立刻知道。
func (e *AlertEngine) Test() error {
	e.mu.Lock()
	hook := e.cfg.Webhook
	e.mu.Unlock()
	if hook == "" {
		return fmt.Errorf("还没填 Webhook 地址")
	}
	return e.send(hook, "流量哨兵：这是一条测试消息，收到就说明配置正确。")
}

// Evaluate 用当前快照评估所有规则。dt 是距上次评估的秒数，
// 用来把速率积分成窗口内流量。
func (e *AlertEngine) Evaluate(snap *Snapshot, dt float64) {
	if snap == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.cfg.Enabled || len(e.cfg.Rules) == 0 {
		return
	}
	now := time.Now()
	// 按匹配名汇总当前速率
	rates := map[string]float64{}
	for _, p := range snap.Procs {
		if p.Pseudo != "" {
			continue
		}
		name := p.Service
		if name == "" {
			name = p.Name
		}
		rates[name] += p.TxRate + p.RxRate
		rates[p.Name] += p.TxRate + p.RxRate
	}
	for _, c := range snap.Conts {
		rates[c.Name] += c.TxRate + c.RxRate
	}

	var fired []AlertEvent
	for _, r := range e.cfg.Rules {
		if r.CooldownMin > 0 {
			if t, ok := e.lastFire[r.ID]; ok && now.Sub(t) < time.Duration(r.CooldownMin)*time.Minute {
				continue
			}
		}
		var val float64
		var unit string
		switch r.Kind {
		case "total":
			// 窗口内累计：按匹配项积分速率
			var sum float64
			for name, v := range rates {
				if r.Match == "" || strings.Contains(name, r.Match) {
					sum += v
				}
			}
			e.winBytes[r.ID] += sum * dt
			ws := e.winStart[r.ID]
			if ws.IsZero() {
				e.winStart[r.ID] = now
				continue
			}
			if now.Sub(ws) < time.Duration(r.WindowMin)*time.Minute {
				continue
			}
			val = e.winBytes[r.ID] / (1 << 20) // MB
			unit = "MB"
			// 窗口结束就重置，下一轮重新开始算
			e.winStart[r.ID] = now
			e.winBytes[r.ID] = 0
			if val < r.Threshold {
				continue
			}
		default:
			var sum float64
			for name, v := range rates {
				if r.Match == "" || strings.Contains(name, r.Match) {
					sum += v
				}
			}
			val = sum / 1024 // KB/s
			unit = "KB/s"
			if val < r.Threshold {
				continue
			}
		}
		name := r.Name
		if name == "" {
			name = r.Match
		}
		if name == "" {
			name = "全部流量"
		}
		text := fmt.Sprintf("【流量哨兵】%s 触发告警：%s 达到 %.1f %s（阈值 %.0f %s）",
			hostname(), name, val, unit, r.Threshold, unit)
		fired = append(fired, AlertEvent{
			At: now.Unix(), Rule: name, Match: r.Match, Value: round1(val), Unit: unit, Text: text,
		})
		e.lastFire[r.ID] = now
	}
	if len(fired) == 0 {
		return
	}
	hook := e.cfg.Webhook
	e.mu.Unlock()
	// 发送放到锁外：webhook 可能慢，不能卡住采集
	for i := range fired {
		err := e.send(hook, fired[i].Text)
		fired[i].Sent = err == nil
		if err != nil {
			fired[i].Err = firstLine(err.Error())
		}
	}
	e.mu.Lock()
	for _, ev := range fired {
		e.events = append([]AlertEvent{ev}, e.events...)
	}
	if len(e.events) > alertEventKeep {
		e.events = e.events[:alertEventKeep]
	}
	if fired[len(fired)-1].Sent {
		e.cfg.LastSent = now.Format("01-02 15:04:05")
		e.cfg.LastErr = ""
	} else {
		e.cfg.LastErr = fired[len(fired)-1].Err
	}
}

// send 按 URL 域名选推送格式。三种机器人的 JSON 结构互不兼容，
// 让用户自己去拼 {"msgtype":...} 是没必要的门槛。
func (e *AlertEngine) send(hook, text string) error {
	u, err := url.Parse(hook)
	if err != nil || u.Host == "" {
		return fmt.Errorf("Webhook 地址不合法")
	}
	var body []byte
	switch {
	case strings.Contains(u.Host, "qyapi.weixin.qq.com"): // 企业微信
		body, _ = json.Marshal(map[string]any{
			"msgtype": "text", "text": map[string]string{"content": text},
		})
	case strings.Contains(u.Host, "dingtalk"): // 钉钉
		body, _ = json.Marshal(map[string]any{
			"msgtype": "text", "text": map[string]string{"content": text},
		})
	case strings.Contains(u.Host, "slack.com"):
		body, _ = json.Marshal(map[string]any{"text": text})
	default: // 通用：text + 结构化字段，方便自己接
		body, _ = json.Marshal(map[string]any{"text": text, "source": "fnnetmon"})
	}
	req, err := http.NewRequest(http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 企业微信/钉钉出错时也返回 200，错误在 body 里
	var out struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	buf := make([]byte, 2048)
	n, _ := resp.Body.Read(buf)
	if n > 0 && json.Unmarshal(buf[:n], &out) == nil && out.ErrCode != 0 {
		return fmt.Errorf("%s (%d)", out.ErrMsg, out.ErrCode)
	}
	return nil
}

func hostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "fnOS"
}

// sortRules 让界面上的规则顺序稳定（按 ID）。
func sortRules(rs []AlertRule) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
}
