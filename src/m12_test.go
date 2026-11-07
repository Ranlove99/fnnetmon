package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// 配置要能原样存回来：告警规则配一次就该一直有效，重启丢配置是最烦的。
func TestAlertSaveLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "alerts.json")
	e := NewAlertEngine(p)
	if err := e.Save(AlertConfig{
		Enabled: true, Webhook: "https://example.com/hook",
		Rules: []AlertRule{{Name: "影视跑满", Match: "影视", Kind: "rate", Threshold: 1024}},
	}); err != nil {
		t.Fatal(err)
	}
	e2 := NewAlertEngine(p)
	c := e2.Config()
	if !c.Enabled || len(c.Rules) != 1 {
		t.Fatalf("配置没读回来：%+v", c)
	}
	if c.Rules[0].ID == 0 {
		t.Error("规则 ID 应由服务端分配")
	}
	if c.Rules[0].CooldownMin != 30 || c.Rules[0].WindowMin != 60 {
		t.Errorf("默认值没补上：%+v", c.Rules[0])
	}
	// 事件不进配置文件：那是一次性的运行态数据
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var back map[string]any
	_ = json.Unmarshal(raw, &back)
	if _, ok := back["events"]; ok {
		t.Error("事件不该写进 alerts.json")
	}
}

func snapWith(proc string, svc string, rate float64) *Snapshot {
	return &Snapshot{Procs: []ProcAgg{{Name: proc, Service: svc, TxRate: rate / 2, RxRate: rate / 2}}}
}

// 超过阈值要触发，触发后进入冷却，冷却期内不重复打扰。
func TestAlertRateAndCooldown(t *testing.T) {
	e := NewAlertEngine(filepath.Join(t.TempDir(), "a.json"))
	if err := e.Save(AlertConfig{
		Enabled: true, Webhook: "http://127.0.0.1:1/never",
		Rules: []AlertRule{{Match: "影视", Kind: "rate", Threshold: 100, CooldownMin: 30}},
	}); err != nil {
		t.Fatal(err)
	}
	// 低于阈值：不触发
	e.Evaluate(snapWith("ffmpeg", "影视", 50*1024), 30)
	if n := len(e.Config().Events); n != 0 {
		t.Fatalf("低于阈值不该触发，得到 %d 条", n)
	}
	// 高于阈值：触发一次（webhook 连不上，事件照样要记下来）
	e.Evaluate(snapWith("ffmpeg", "影视", 500*1024), 30)
	evs := e.Config().Events
	if len(evs) != 1 {
		t.Fatalf("超过阈值应触发 1 条，得到 %d", len(evs))
	}
	if evs[0].Sent {
		t.Error("webhook 连不上，不该标记为已发送")
	}
	if evs[0].Value < 400 {
		t.Errorf("记录的值不对：%v", evs[0].Value)
	}
	// 冷却期内再超也不重复
	e.Evaluate(snapWith("ffmpeg", "影视", 900*1024), 30)
	if n := len(e.Config().Events); n != 1 {
		t.Errorf("冷却期内不该重复触发，得到 %d 条", n)
	}
}

// 关掉开关就完全静默，即使规则还在。
func TestAlertDisabled(t *testing.T) {
	e := NewAlertEngine(filepath.Join(t.TempDir(), "a.json"))
	_ = e.Save(AlertConfig{
		Enabled: false, Webhook: "http://127.0.0.1:1/never",
		Rules: []AlertRule{{Match: "影视", Kind: "rate", Threshold: 1}},
	})
	e.Evaluate(snapWith("ffmpeg", "影视", 999*1024), 30)
	if n := len(e.Config().Events); n != 0 {
		t.Errorf("关掉后不该触发，得到 %d 条", n)
	}
}

// 通用 webhook 的 JSON 结构：必须有 text，方便任何接收端至少能显示一句话。
func TestAlertWebhookPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"errcode":0}`))
	}))
	defer srv.Close()

	e := NewAlertEngine(filepath.Join(t.TempDir(), "a.json"))
	if err := e.send(srv.URL, "测试消息"); err != nil {
		t.Fatal(err)
	}
	if got["text"] != "测试消息" {
		t.Errorf("payload 里没有 text：%v", got)
	}
	if got["source"] != "fnnetmon" {
		t.Errorf("payload 缺 source：%v", got)
	}
}

// 企业微信/钉钉出错也返回 HTTP 200，错误在 body 的 errcode 里，
// 不检查就会把「token 过期」当成发送成功。
func TestAlertWebhookErrCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook url"}`))
	}))
	defer srv.Close()
	e := NewAlertEngine(filepath.Join(t.TempDir(), "a.json"))
	if err := e.send(srv.URL, "x"); err == nil {
		t.Fatal("errcode 非 0 时应该报错")
	}
}
