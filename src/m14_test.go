package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// 「应用」维度必须把同一服务下的多个进程合并成一行，并把容器流量算进对应应用。
//
// 历史库只存进程维度，归并在查询时做——这条路径没有落库，最容易漏的是
// 「同一个桶里同一个 key 出现多行要累加」，写成赋值就会只剩最后一行的值。
func TestHistorySvcMergesProcs(t *testing.T) {
	s := newTestStore(t)
	base := alignBucket(time.Now().Unix(), 60) - 600

	rows := []AggRow{
		// 一个应用挂两个进程（node + ffmpeg 都属于「影视」），同一个桶
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "node", Tx: 100, Rx: 900},
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "ffmpeg", Tx: 200, Rx: 300},
		// 另一个应用
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "nginx", Tx: 10, Rx: 20},
		// 容器流量（独立 netns，只存在于 cont 维度）
		{Bucket: base, Gran: "1m", Dim: "cont", Key: "qbittorrent", Tx: 7, Rx: 70},
	}
	if err := s.Flush(rows); err != nil {
		t.Fatalf("flush: %v", err)
	}

	svcOf := map[string]string{"node": "影视", "ffmpeg": "影视", "nginx": "trim-nginx"}
	h, err := s.HistorySvc("24h", 8, svcOf)
	if err != nil {
		t.Fatalf("history svc: %v", err)
	}
	if h.Dim != "svc" {
		t.Fatalf("Dim = %q, want svc", h.Dim)
	}

	got := map[string]Series{}
	for _, ser := range h.Series {
		got[ser.Key] = ser
	}
	if len(got) != 3 {
		t.Fatalf("应用数 = %d, want 3（影视 / trim-nginx / qbittorrent）：%v", len(got), keysOf(h.Series))
	}

	// 两个进程必须合并：100+200 上行、900+300 下行
	film, ok := got["影视"]
	if !ok {
		t.Fatalf("没有「影视」这一行：%v", keysOf(h.Series))
	}
	if film.SumT != 300 || film.SumR != 1200 {
		t.Fatalf("影视 = tx %d rx %d, want 300/1200（两个进程要累加，不是取最后一个）", film.SumT, film.SumR)
	}
	// 容器用容器名当应用名
	qb, ok := got["qbittorrent"]
	if !ok {
		t.Fatalf("容器应该用容器名成行：%v", keysOf(h.Series))
	}
	if qb.SumT != 7 || qb.SumR != 70 {
		t.Fatalf("qbittorrent = tx %d rx %d, want 7/70", qb.SumT, qb.SumR)
	}
	// 容器来源要打标，前端靠它显示「容器」标签
	if !qb.Cont {
		t.Fatal("容器来源的序列应该带 Cont 标记")
	}
	if film.Cont {
		t.Fatal("纯进程来源的序列不该带 Cont 标记")
	}
	// 进程名本身不该再单独出现
	if _, bad := got["node"]; bad {
		t.Fatal("归并后不该还留着进程名 node")
	}
}

// 已经退出、查不到服务归属的进程，按它自己的名字成行——
// 丢掉的话历史总量会少一块，用户会以为是采集漏了。
func TestHistorySvcKeepsUnknownProc(t *testing.T) {
	s := newTestStore(t)
	base := alignBucket(time.Now().Unix(), 60) - 300

	if err := s.Flush([]AggRow{
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "gone-app", Tx: 5, Rx: 50},
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "未归因", Tx: 1, Rx: 10},
	}); err != nil {
		t.Fatalf("flush: %v", err)
	}

	h, err := s.HistorySvc("24h", 8, map[string]string{}) // 当前快照里一个都没有
	if err != nil {
		t.Fatalf("history svc: %v", err)
	}
	keys := map[string]bool{}
	for _, ser := range h.Series {
		keys[ser.Key] = true
	}
	if !keys["gone-app"] {
		t.Fatalf("查不到服务归属的进程应该按原名成行，实际 %v", keys)
	}
	if !keys["未归因"] {
		t.Fatalf("「未归因」必须原样保留，实际 %v", keys)
	}
}

// 明细导出走「应用」维度时，名称列必须是应用名，且同一个桶里多个进程要合并成一行。
func TestExportRowsSvc(t *testing.T) {
	s := newTestStore(t)
	base := alignBucket(time.Now().Unix(), 60) - 300

	if err := s.Flush([]AggRow{
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "node", Tx: 100, Rx: 900},
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "ffmpeg", Tx: 200, Rx: 300},
		{Bucket: base, Gran: "1m", Dim: "cont", Key: "qbittorrent", Tx: 7, Rx: 70},
	}); err != nil {
		t.Fatalf("flush: %v", err)
	}

	var buf bytes.Buffer
	if err := s.ExportRowsSvc(&buf, "24h", map[string]string{"node": "影视", "ffmpeg": "影视"}); err != nil {
		t.Fatalf("export: %v", err)
	}
	out := buf.String()
	// BOM 由 beginCSV 在 HTTP 层写，这里只验内容
	if !strings.HasPrefix(out, "时间,维度,名称,下行字节,上行字节,下行MB,上行MB\n") {
		t.Fatalf("表头不对: %q", strings.SplitN(out, "\n", 2)[0])
	}
	if !strings.Contains(out, "svc,影视,1200,300") {
		t.Fatalf("导出的应用行应该是 svc,影视,下行1200,上行300，实际：\n%s", out)
	}
	if strings.Contains(out, ",node,") || strings.Contains(out, ",ffmpeg,") {
		t.Fatalf("导出不该出现进程名：\n%s", out)
	}
	if !strings.Contains(out, "svc,qbittorrent,70,7") {
		t.Fatalf("容器行缺失：\n%s", out)
	}
	// 同一个桶只能有一行「影视」，多了说明没合并
	if n := strings.Count(out, ",影视,"); n != 1 {
		t.Fatalf("「影视」出现了 %d 行，应该合并成 1 行：\n%s", n, out)
	}
}
