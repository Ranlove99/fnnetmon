package main

import (
	"encoding/json"
	"net/http"
)

// routeMisc 注册剩下的接口：地理数据、自检、告警、首页。
func (s *server) routeMisc(mux *http.ServeMux) {
	mux.HandleFunc("/api/dns", s.handleDNS)
	mux.HandleFunc("/api/geo/fetch", s.handleGeoFetch)
	mux.HandleFunc("/api/geo/remove", s.handleGeoRemove)
	mux.HandleFunc("/api/selfcheck", s.handleSelfCheck)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/alerts/test", s.handleAlertTest)
	mux.HandleFunc("/", s.handleIndex)
}

// handleDNS 返回域名归因与地理数据的状态。
// 界面用它在概览页显示「能不能看到域名」，以及省市数据装没装、装到哪一步了。
func (s *server) handleDNS(w http.ResponseWriter, r *http.Request) {
	jsonReply(w, map[string]any{
		"stats":   s.dom.Stats(),
		"geo":     s.geo.Status(),
		"geo_job": s.geoJob.State(),
	}, 200)
}

// handleGeoFetch 起一个后台下载任务。
//
// 48MB 在 NAS 上要几分钟，同步 HTTP 必超时，所以这里只负责起个头，
// 进度从 /api/dns 的 geo_job 里读，前端每秒轮询一次。
func (s *server) handleGeoFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonReply(w, map[string]any{"error": "只接受 POST"}, 405)
		return
	}
	if err := s.geoJob.Start(); err != nil {
		jsonReply(w, map[string]any{"error": err.Error()}, 409)
		return
	}
	jsonReply(w, map[string]any{"ok": true, "job": s.geoJob.State()}, 200)
}

func (s *server) handleGeoRemove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonReply(w, map[string]any{"error": "只接受 POST"}, 405)
		return
	}
	if err := s.geoJob.Remove(); err != nil {
		jsonReply(w, map[string]any{"error": err.Error()}, 500)
		return
	}
	jsonReply(w, map[string]any{"ok": true, "geo": s.geo.Status()}, 200)
}

// handleSelfCheck 运行状态自检。长跑验证靠它：装好后隔几天拉一次，
// 对比 RSS / goroutine / fd 有没有缓慢上涨。
func (s *server) handleSelfCheck(w http.ResponseWriter, r *http.Request) {
	jsonReply(w, BuildSelfCheck(s.hub, s.store, s.fw, s.peers), 200)
}

// handleAlerts 读写告警配置。规则存 alerts.json，改完立刻生效（下一轮评估就用新的）。
func (s *server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonReply(w, s.alerts.Config(), 200)
		return
	}
	var in AlertConfig
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		jsonReply(w, map[string]any{"error": "参数解析失败：" + firstLine(err.Error())}, 400)
		return
	}
	if err := s.alerts.Save(in); err != nil {
		jsonReply(w, map[string]any{"error": err.Error()}, 500)
		return
	}
	jsonReply(w, s.alerts.Config(), 200)
}

func (s *server) handleAlertTest(w http.ResponseWriter, r *http.Request) {
	if err := s.alerts.Test(); err != nil {
		jsonReply(w, map[string]any{"error": err.Error()}, 400)
		return
	}
	jsonReply(w, map[string]any{"ok": true}, 200)
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(dashboardHTML))
}
