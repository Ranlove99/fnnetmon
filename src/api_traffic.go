package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// routeTraffic 注册「看流量」的接口：实时快照、历史、区间排行、CSV 导出、诊断页。
func (s *server) routeTraffic(mux *http.ServeMux) {
	mux.HandleFunc("/api/snapshot", s.handleSnapshot)
	mux.HandleFunc("/api/diag", s.handleDiag)
	mux.HandleFunc("/api/debug", s.handleDebug)
	mux.HandleFunc("/api/history", s.handleHistory)
	mux.HandleFunc("/api/rank", s.handleRank)
	mux.HandleFunc("/api/export", s.handleExportRows)
	mux.HandleFunc("/api/export/rank", s.handleExportRank)
	mux.HandleFunc("/diag", s.handleDiagPage)
}

func (s *server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	b, err := json.Marshal(s.hub.Snapshot())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// handleDiag 返回 M0 探针报告。缓存 5 秒——探针要扫 /proc 和 netlink，
// 前端刷新一次就全量跑一遍太重。
func (s *server) handleDiag(w http.ResponseWriter, r *http.Request) {
	rep := s.dc.get(5 * time.Second)
	if r.URL.Query().Get("refresh") != "" {
		rep = Collect()
		s.dc.mu.Lock()
		s.dc.rep, s.dc.when = rep, time.Now()
		s.dc.mu.Unlock()
	}
	rep.Gateway = gatewayInfo(r)
	b, _ := json.MarshalIndent(rep, "", "  ")
	_ = os.WriteFile(filepath.Join(s.varDir, "diag.json"), b, 0o644)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

func (s *server) handleDebug(w http.ResponseWriter, r *http.Request) {
	b, _ := json.MarshalIndent(s.hub.Debug(), "", "  ")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(b)
}

// handleHistory 返回趋势图数据。
//
// dim=svc 是「应用」维度：进程按服务归并、容器用容器名。
// 历史库只存进程维度，归并发生在查询时（见 Store.HistorySvc）。
func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{"error":"历史库不可用"}`))
		return
	}
	q := r.URL.Query()
	dim := q.Get("dim")
	if dim == "" {
		dim = "proc"
	}
	rng := q.Get("range")
	if rng == "" {
		rng = "24h"
	}
	top, _ := strconv.Atoi(q.Get("top"))

	var h *History
	var err error
	if dim == "svc" {
		h, err = s.store.HistorySvc(rng, top, s.hub.ProcServices())
	} else {
		h, err = s.store.History(dim, rng, top)
	}
	if err != nil {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(500)
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		_, _ = w.Write(b)
		return
	}
	b, err := json.Marshal(h)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// handleRank 返回区间排行：回答「最近一小时/一天，到底是谁在跑流量」。
// 实时排行前端直接用 /api/snapshot 算，这个接口只负责历史区间。
func (s *server) handleRank(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		jsonReply(w, map[string]string{"error": "历史库不可用，只能看实时排行"}, 503)
		return
	}
	q := r.URL.Query()
	rng := q.Get("range")
	if rng == "" {
		rng = "24h"
	}
	by := q.Get("by")
	if by != "proc" {
		by = "svc"
	}
	rows, err := s.store.Rank(rng, by, s.hub.ProcServices(), 40)
	if err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 500)
		return
	}
	jsonReply(w, map[string]any{"range": rng, "by": by, "rows": rows}, 200)
}

// handleExportRows 导时序明细（时间 × 名称），看趋势、做二次分析。
//
// 带 UTF-8 BOM —— 不带的话 Excel 打开中文全是乱码，这是最常见的抱怨。
func (s *server) handleExportRows(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "历史库不可用", 503)
		return
	}
	q := r.URL.Query()
	dim := q.Get("dim")
	if dim == "" {
		dim = "proc"
	}
	rng := q.Get("range")
	if rng == "" {
		rng = "24h"
	}
	beginCSV(w, fmt.Sprintf("fnnetmon-%s-%s-%s.csv", dim, rng, time.Now().Format("20060102-1504")))
	var err error
	if dim == "svc" {
		err = s.store.ExportRowsSvc(w, rng, s.hub.ProcServices())
	} else {
		err = s.store.ExportRows(w, dim, rng)
	}
	if err != nil {
		// 头已经发出去了，只能记日志，不能改状态码
		fmt.Fprintf(os.Stderr, "[fnnetmon] export rows: %v\n", err)
	}
}

// handleExportRank 导区间汇总（一行一个服务），写周报直接贴。
func (s *server) handleExportRank(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "历史库不可用", 503)
		return
	}
	q := r.URL.Query()
	rng := q.Get("range")
	if rng == "" {
		rng = "24h"
	}
	by := q.Get("by")
	if by != "proc" {
		by = "svc"
	}
	beginCSV(w, fmt.Sprintf("fnnetmon-排行-%s-%s-%s.csv", by, rng, time.Now().Format("20060102-1504")))
	if err := s.store.ExportRank(w, rng, by, s.hub.ProcServices()); err != nil {
		fmt.Fprintf(os.Stderr, "[fnnetmon] export rank: %v\n", err)
	}
}

func (s *server) handleDiagPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}
