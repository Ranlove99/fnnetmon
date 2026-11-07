package main

import (
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// 时间桶必须按本地时区对齐，否则「按天」的边界会落在北京时间 08:00。
func TestAlignBucket(t *testing.T) {
	_, off := time.Now().Zone()
	o := int64(off)

	// 对齐到分钟后必须能被 60 整除（相对本地时间）
	ts := time.Date(2026, 3, 5, 14, 37, 12, 0, time.Local).Unix()
	got := alignBucket(ts, 60)
	want := time.Date(2026, 3, 5, 14, 37, 0, 0, time.Local).Unix()
	if got != want {
		t.Fatalf("align 1m: got %d want %d", got, want)
	}

	// 按天对齐必须落在本地 00:00
	got = alignBucket(ts, 86400)
	want = time.Date(2026, 3, 5, 0, 0, 0, 0, time.Local).Unix()
	if got != want {
		t.Fatalf("align 1d: got %s want %s",
			time.Unix(got, 0).Format("2006-01-02 15:04"),
			time.Unix(want, 0).Format("2006-01-02 15:04"))
	}
	if (got+o)%86400 != 0 {
		t.Fatalf("align 1d not multiple of 86400 in local terms: %d", got+o)
	}
}

// 分钟数据写入后能按 24h 范围查回来，topN 之外的合并成「其他」。
func TestHistoryAndOthers(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()
	base := alignBucket(now, 60) - 600 // 10 分钟前

	rows := []AggRow{
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "chrome", Tx: 100, Rx: 900},
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "curl", Tx: 300, Rx: 100},
		{Bucket: base + 60, Gran: "1m", Dim: "proc", Key: "chrome", Tx: 50, Rx: 450},
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "tiny", Tx: 1, Rx: 1},
	}
	if err := s.Flush(rows); err != nil {
		t.Fatalf("flush: %v", err)
	}

	h, err := s.History("proc", "24h", 2)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if h.Gran != "1m" || h.Step != 60 {
		t.Fatalf("gran/step = %s/%d", h.Gran, h.Step)
	}
	if len(h.Buckets) != 1441 {
		t.Fatalf("buckets = %d, want 1441", len(h.Buckets))
	}
	// chrome 1500 > curl 400 > tiny 2，top2 应为 chrome、curl，剩下归「其他」
	if len(h.Series) != 3 {
		t.Fatalf("series = %d, want 3 (%v)", len(h.Series), keysOf(h.Series))
	}
	if h.Series[0].Key != "chrome" || h.Series[0].SumT != 150 || h.Series[0].SumR != 1350 {
		t.Fatalf("series[0] = %s tx=%d rx=%d", h.Series[0].Key, h.Series[0].SumT, h.Series[0].SumR)
	}
	if h.Series[1].Key != "curl" {
		t.Fatalf("series[1] = %s", h.Series[1].Key)
	}
	if h.Series[2].Key != "其他" || h.Series[2].SumT != 1 {
		t.Fatalf("series[2] = %s tx=%d", h.Series[2].Key, h.Series[2].SumT)
	}
	// 每个序列的点数必须和时间轴一致，否则前端画图会错位
	for _, ser := range h.Series {
		if len(ser.Tx) != len(h.Buckets) || len(ser.Rx) != len(h.Buckets) {
			t.Fatalf("%s 点数 %d/%d 与时间轴 %d 不一致", ser.Key, len(ser.Tx), len(ser.Rx), len(h.Buckets))
		}
	}
	if h.TotalT != 451 || h.TotalR != 1451 {
		t.Fatalf("total = %d/%d, want 451/1451", h.TotalT, h.TotalR)
	}
}

// rollup 之后 1h / 1d 粒度都要能查到，且不能把边界桶写成半个桶的和。
func TestRollup(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()
	h0 := alignBucket(now, 3600)

	// 造 3 个小时的分钟数据，每小时 10 分钟、每分钟 100 字节
	var rows []AggRow
	for i := int64(0); i < 3; i++ {
		for j := int64(0); j < 10; j++ {
			rows = append(rows, AggRow{
				Bucket: h0 - i*3600 + j*60, Gran: "1m", Dim: "proc",
				Key: "svc", Tx: 100, Rx: 0,
			})
		}
	}
	if err := s.Flush(rows); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := s.Rollup(); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	// 再跑一次必须幂等，不能翻倍
	if err := s.Rollup(); err != nil {
		t.Fatalf("rollup #2: %v", err)
	}

	h, err := s.History("proc", "7d", 5)
	if err != nil {
		t.Fatalf("history 7d: %v", err)
	}
	if h.Gran != "1h" || h.Step != 3600 {
		t.Fatalf("gran = %s step = %d", h.Gran, h.Step)
	}
	// 3 小时 × 10 分钟 × 100 = 3000
	if h.TotalT != 3000 {
		t.Fatalf("7d total tx = %d, want 3000 (rollup 不幂等或边界桶被截断)", h.TotalT)
	}

	hd, err := s.History("proc", "30d", 5)
	if err != nil {
		t.Fatalf("history 30d: %v", err)
	}
	if hd.Gran != "1d" {
		t.Fatalf("gran 30d = %s", hd.Gran)
	}
	if hd.TotalT != 3000 {
		t.Fatalf("30d total tx = %d, want 3000", hd.TotalT)
	}
}

// 保留期外的数据必须被清掉，否则 4GB 设备迟早撑爆。
func TestPurge(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	rows := []AggRow{
		{Bucket: alignBucket(now, 60) - 8*86400, Gran: "1m", Dim: "proc", Key: "old", Tx: 1, Rx: 1},
		{Bucket: alignBucket(now, 60), Gran: "1m", Dim: "proc", Key: "new", Tx: 2, Rx: 2},
		{Bucket: alignBucket(now, 86400) - 500*86400, Gran: "1d", Dim: "proc", Key: "ancient", Tx: 3, Rx: 3},
	}
	if err := s.Flush(rows); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if err := s.Purge(); err != nil {
		t.Fatalf("purge: %v", err)
	}

	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM agg WHERE key='old'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("8 天前的 1m 数据没被清掉")
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM agg WHERE key='new'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("当前数据被误删")
	}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM agg WHERE key='ancient'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("500 天前的 1d 数据没被清掉")
	}
}

func TestExportRows(t *testing.T) {
	s := newTestStore(t)
	base := alignBucket(time.Now().Unix(), 60) - 120
	if err := s.Flush([]AggRow{
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "含,逗号", Tx: 10, Rx: 20},
	}); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	if err := s.ExportRows(&buf, "proc", "1h"); err != nil {
		t.Fatal(err)
	}
	csv := buf.String()
	if !strings.HasPrefix(csv, "时间,维度,名称,下行字节,上行字节,下行MB,上行MB\n") {
		t.Fatalf("表头不对: %q", strings.SplitN(csv, "\n", 2)[0])
	}
	// 带逗号的 key 必须被引号包起来，否则 CSV 列会错位
	if !strings.Contains(csv, `"含,逗号"`) {
		t.Fatalf("含逗号的 key 没加引号:\n%s", csv)
	}
	// 下行在前、上行在后，和界面上的 ↓ / ↑ 一致；反了用户对不上号
	if !strings.Contains(csv, ",20,10,") {
		t.Fatalf("下行/上行列顺序不对:\n%s", csv)
	}
}

func TestExportRank(t *testing.T) {
	s := newTestStore(t)
	base := alignBucket(time.Now().Unix(), 60) - 120
	if err := s.Flush([]AggRow{
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "ffmpeg", Tx: 100, Rx: 300},
		{Bucket: base, Gran: "1m", Dim: "proc", Key: "curl", Tx: 100, Rx: 100},
	}); err != nil {
		t.Fatal(err)
	}
	svcOf := map[string]string{"ffmpeg": "影视", "curl": "其它"}
	var buf strings.Builder
	if err := s.ExportRank(&buf, "1h", "svc", svcOf); err != nil {
		t.Fatal(err)
	}
	csv := buf.String()
	lines := strings.Split(strings.TrimSpace(csv), "\n")
	if len(lines) != 3 {
		t.Fatalf("应有表头 + 2 行，实际 %d 行:\n%s", len(lines), csv)
	}
	// 第一行必须是流量最大的那个，且占比 66.67%
	if !strings.HasPrefix(lines[1], "1,影视,服务,") {
		t.Fatalf("排行顺序或服务归并错了: %s", lines[1])
	}
	if !strings.HasSuffix(lines[1], ",66.67") {
		t.Fatalf("占比算错: %s", lines[1])
	}
	// by=proc 时维度列要写「进程」，不能写「服务」
	buf.Reset()
	if err := s.ExportRank(&buf, "1h", "proc", svcOf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), ",进程,") {
		t.Fatalf("by=proc 时维度列不对:\n%s", buf.String())
	}
}

func keysOf(ss []Series) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Key
	}
	return out
}
