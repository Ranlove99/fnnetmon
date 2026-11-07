package main

import (
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// AggRow 是一条聚合记录。bucket 为对齐后的 unix 秒。
type AggRow struct {
	Bucket int64
	Gran   string
	Dim    string
	Key    string
	Tx     int64
	Rx     int64
}

type Store struct {
	mu   sync.Mutex
	db   *sql.DB
	path string
}

// 保留策略：分钟级 7 天，小时级 90 天，天级 400 天。
var retention = map[string]time.Duration{
	"1m": 7 * 24 * time.Hour,
	"1h": 90 * 24 * time.Hour,
	"1d": 400 * 24 * time.Hour,
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "fnnetmon.db")
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)&_pragma=cache_size(-4096)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)

	s := &Store{db: db, path: path}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS agg (
  bucket INTEGER NOT NULL,
  gran   TEXT    NOT NULL,
  dim    TEXT    NOT NULL,
  key    TEXT    NOT NULL,
  tx     INTEGER NOT NULL,
  rx     INTEGER NOT NULL,
  PRIMARY KEY (bucket, gran, dim, key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_agg_query ON agg(dim, gran, bucket);
-- rollup / purge 都是按 gran + bucket 扫，没有这个索引会每 5 分钟全表扫一遍
CREATE INDEX IF NOT EXISTS idx_agg_gran ON agg(gran, bucket);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);

-- peer：某个程序第一次连某个远端地址的记录（Little Snitch 的核心体验）
-- 主键是 (proc, ip)：同一个程序连同一台主机的不同端口算同一条对端
CREATE TABLE IF NOT EXISTS peer (
  proc    TEXT    NOT NULL,
  ip      TEXT    NOT NULL,
  cont    TEXT    NOT NULL DEFAULT '',
  cg      TEXT    NOT NULL DEFAULT '',
  path    TEXT    NOT NULL DEFAULT '',
  port    INTEGER NOT NULL DEFAULT 0,
  proto   TEXT    NOT NULL DEFAULT '',
  first   INTEGER NOT NULL,
  last    INTEGER NOT NULL,
  hits    INTEGER NOT NULL DEFAULT 1,
  tx      INTEGER NOT NULL DEFAULT 0,
  rx      INTEGER NOT NULL DEFAULT 0,
  verdict TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (proc, ip)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_peer_first ON peer(first);
CREATE INDEX IF NOT EXISTS idx_peer_verdict ON peer(verdict, first);

-- rule：出向拦截规则。cgroup 存路径而不是 inode，
-- 因为 inode 会随 cgroup 重建而变，路径才能跨服务重启稳定命中。
-- kind=ip 时 ip 列是地址/CIDR；kind=domain 时 domain 列是域名，下发时才解析成地址。
CREATE TABLE IF NOT EXISTS rule (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  action  TEXT    NOT NULL,
  proc    TEXT    NOT NULL DEFAULT '',
  cont    TEXT    NOT NULL DEFAULT '',
  cgroup  TEXT    NOT NULL DEFAULT '',
  ip      TEXT    NOT NULL DEFAULT '',
  port    INTEGER NOT NULL DEFAULT 0,
  kind    TEXT    NOT NULL DEFAULT 'ip',
  domain  TEXT    NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 0,
  note    TEXT    NOT NULL DEFAULT '',
  created INTEGER NOT NULL,
  hits    INTEGER NOT NULL DEFAULT 0
);
`); err != nil {
		return err
	}

	// 增量列。SQLite 的 ADD COLUMN 没有 IF NOT EXISTS，重复执行必然报错，
	// 这里只吞掉「列已存在」这一种，其它错误（磁盘满之类）照样要能看见。
	for _, c := range []struct{ table, col, decl string }{
		{"peer", "path", "TEXT NOT NULL DEFAULT ''"},
		{"rule", "kind", "TEXT NOT NULL DEFAULT 'ip'"},
		{"rule", "domain", "TEXT NOT NULL DEFAULT ''"},
	} {
		_, aerr := s.db.Exec("ALTER TABLE " + c.table + " ADD COLUMN " + c.col + " " + c.decl)
		if aerr != nil && !strings.Contains(aerr.Error(), "duplicate column") {
			fmt.Fprintf(os.Stderr, "[fnnetmon] migrate %s.%s: %v\n", c.table, c.col, aerr)
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// Flush 写入一批聚合行（同主键覆盖）。
func (s *Store) Flush(rows []AggRow) error {
	if len(rows) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO agg(bucket,gran,dim,key,tx,rx) VALUES(?,?,?,?,?,?)
ON CONFLICT(bucket,gran,dim,key) DO UPDATE SET tx=excluded.tx, rx=excluded.rx`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Bucket, r.Gran, r.Dim, r.Key, r.Tx, r.Rx); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// alignBucket 把时间戳对齐到 width 秒的整数倍。
// 按本地时区对齐，否则「按天」的桶边界会落在北京时间 08:00，看图很别扭。
func alignBucket(ts, width int64) int64 {
	_, off := time.Now().Zone()
	o := int64(off)
	return ((ts+o)/width)*width - o
}

// Rollup 从细粒度汇总出粗粒度，保证图上任意时间范围都有数据。
func (s *Store) Rollup() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, off := time.Now().Zone()
	o := int64(off)
	now := time.Now().Unix()

	steps := []struct {
		dst, src string
		width    int64
	}{
		{"1h", "1m", 3600},
		{"1d", "1h", 86400},
	}
	for _, st := range steps {
		// 只重算最近 3 天，避免每次全表扫。
		// 起点必须对齐到目标粒度，否则边界那个桶会被「半个桶」的和覆盖掉。
		endB := alignBucket(now, st.width)
		startB := endB - 3*86400

		q := fmt.Sprintf(`
INSERT INTO agg(bucket,gran,dim,key,tx,rx)
SELECT (((bucket+?)/%d)*%d)-?, '%s', dim, key, SUM(tx), SUM(rx)
FROM agg WHERE gran='%s' AND bucket>=?
GROUP BY (((bucket+?)/%d)*%d)-?, dim, key
ON CONFLICT(bucket,gran,dim,key) DO UPDATE SET tx=excluded.tx, rx=excluded.rx`,
			st.width, st.width, st.dst, st.src, st.width, st.width)
		if _, err := s.db.Exec(q, o, o, startB, o, o, o); err != nil {
			return err
		}
	}
	return nil
}

// Purge 删除超过保留期的数据。
func (s *Store) Purge() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for gran, keep := range retention {
		cut := now - int64(keep.Seconds())
		if _, err := s.db.Exec(`DELETE FROM agg WHERE gran=? AND bucket<?`, gran, cut); err != nil {
			return err
		}
	}
	// 回收空间（WAL 下 incremental_vacuum 需要 auto_vacuum=INCREMENTAL，这里只在必要时 checkpoint）
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return nil
}

// ---- 查询 ----

type Series struct {
	Key  string  `json:"key"`
	Tx   []int64 `json:"tx"`
	Rx   []int64 `json:"rx"`
	SumT int64   `json:"sum_tx"`
	SumR int64   `json:"sum_rx"`
	// Cont 表示这条序列有容器来源（只可能在 svc 维度出现）。
	// 前端据此打「容器」标签——应用名和容器名混在一列里，不标一下分不清。
	Cont bool `json:"cont,omitempty"`
}

type History struct {
	Dim     string   `json:"dim"`
	Range   string   `json:"range"`
	Gran    string   `json:"gran"`
	Step    int64    `json:"step"`
	Buckets []int64  `json:"buckets"`
	Series  []Series `json:"series"`
	TotalT  int64    `json:"total_tx"`
	TotalR  int64    `json:"total_rx"`
}

// granFor 按时间跨度选择合适粒度：跨度越长，粒度越粗，避免一次拉太多点。
func granFor(rng string) (string, time.Duration) {
	switch rng {
	case "1h":
		return "1m", time.Hour
	case "6h":
		return "1m", 6 * time.Hour
	case "24h":
		return "1m", 24 * time.Hour
	case "7d":
		return "1h", 7 * 24 * time.Hour
	case "30d":
		return "1d", 30 * 24 * time.Hour
	default:
		return "1m", 24 * time.Hour
	}
}

// stepFor 返回粒度对应的桶宽（秒）。时间轴和区间边界都按它对齐，
// 三处各写一遍 switch 太容易漏改，抽出来。
func stepFor(gran string) int64 {
	switch gran {
	case "1h":
		return 3600
	case "1d":
		return 86400
	default:
		return 60
	}
}

func (s *Store) History(dim, rng string, topN int) (*History, error) {
	if dim == "" {
		dim = "proc"
	}
	return s.historyQuery([]string{dim}, dim, rng, topN, nil)
}

// HistorySvc 按「应用」聚合历史时序。
//
// 历史库只存了进程维度（服务维度在查询时归并，多存一份会让 agg 表体积接近翻倍），
// 所以这里同时查 proc 和 cont 两个维度：proc 的 key 是进程名，经 svcOf 归并回服务名；
// cont 的 key 本来就是容器名，直接当应用名用——容器在独立 netns 里，宿主机
// 看不到它的 socket，容器流量只存在于 cont 维度，两者不会重复计算。
//
// 已知近似：进程退出后不在当前快照里，svcOf 查不到，会按它自己的进程名单独成行。
// 和 Rank 的近似一致——真正偷跑的服务进程通常是常驻的。
func (s *Store) HistorySvc(rng string, topN int, svcOf map[string]string) (*History, error) {
	return s.historyQuery([]string{"proc", "cont"}, "svc", rng, topN, svcOf)
}

// historyQuery 是 History / HistorySvc 的公共实现。
//
// dims 是要查的库内维度，dimName 是回给前端的维度名（可能和 dims 不同：svc 查两个维度）。
// svcOf 非空时把 proc 维度的 key 归并到服务名；同一输出 key 的多个来源在同一个桶里累加。
func (s *Store) historyQuery(dims []string, dimName, rng string, topN int, svcOf map[string]string) (*History, error) {
	gran, span := granFor(rng)
	if topN <= 0 || topN > 20 {
		topN = 8
	}
	step := stepFor(gran)

	now := time.Now().Unix()
	end := alignBucket(now, step)
	start := end - int64(span.Seconds())

	// 占位符按维度个数拼，别用字符串拼值——参数一律走 args。
	ph := strings.TrimSuffix(strings.Repeat("?,", len(dims)), ",")
	args := make([]any, 0, len(dims)+3)
	args = append(args, gran)
	for _, d := range dims {
		args = append(args, d)
	}
	args = append(args, start, end)

	rows, err := s.db.Query(`
SELECT bucket, dim, key, SUM(tx), SUM(rx) FROM agg
WHERE gran=? AND dim IN (`+ph+`) AND bucket>=? AND bucket<=?
GROUP BY bucket, dim, key ORDER BY bucket`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keyOf := func(dim, k string) string {
		if svcOf != nil && dim == "proc" {
			if v, ok := svcOf[k]; ok && v != "" {
				return v
			}
		}
		return k
	}

	type kv struct{ tx, rx int64 }
	byKey := map[string]map[int64]kv{}
	totals := map[string]int64{}
	fromCont := map[string]bool{} // 这个应用名是不是有容器来源
	for rows.Next() {
		var b int64
		var d, k string
		var tx, rx int64
		if err := rows.Scan(&b, &d, &k, &tx, &rx); err != nil {
			continue
		}
		out := keyOf(d, k)
		m := byKey[out]
		if m == nil {
			m = map[int64]kv{}
			byKey[out] = m
		}
		// 归并后同一 key 同一个桶可能有多行（多个进程、或进程+容器），必须累加。
		// 原来这里直接赋值，只有在「一个 key 一个桶恰好一行」时才碰巧正确。
		old := m[b]
		m[b] = kv{old.tx + tx, old.rx + rx}
		totals[out] += tx + rx
		if d == "cont" {
			fromCont[out] = true
		}
	}

	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return totals[keys[i]] > totals[keys[j]] })

	// 时间轴
	n := int((end - start) / step)
	if n < 0 {
		n = 0
	}
	buckets := make([]int64, 0, n)
	for i := 0; i <= n; i++ {
		buckets = append(buckets, start+int64(i)*step)
	}

	h := &History{Dim: dimName, Range: rng, Gran: gran, Step: step, Buckets: buckets}
	othersT, othersR := make([]int64, len(buckets)), make([]int64, len(buckets))

	for i, k := range keys {
		if i >= topN {
			for bi, b := range buckets {
				if v, ok := byKey[k][b]; ok {
					othersT[bi] += v.tx
					othersR[bi] += v.rx
				}
			}
			continue
		}
		ser := Series{Key: k, Tx: make([]int64, len(buckets)), Rx: make([]int64, len(buckets)),
			Cont: fromCont[k]}
		for bi, b := range buckets {
			if v, ok := byKey[k][b]; ok {
				ser.Tx[bi] = v.tx
				ser.Rx[bi] = v.rx
				ser.SumT += v.tx
				ser.SumR += v.rx
			}
		}
		h.Series = append(h.Series, ser)
		h.TotalT += ser.SumT
		h.TotalR += ser.SumR
	}
	if len(keys) > topN {
		ser := Series{Key: "其他", Tx: othersT, Rx: othersR}
		for i := range othersT {
			ser.SumT += othersT[i]
			ser.SumR += othersR[i]
		}
		h.Series = append(h.Series, ser)
		h.TotalT += ser.SumT
		h.TotalR += ser.SumR
	}
	return h, nil
}

// RankRow 是一个排行条目。Tx/Rx 是区间内的累计字节数。
type RankRow struct {
	Name  string `json:"name"`
	Tx    int64  `json:"tx"`
	Rx    int64  `json:"rx"`
	Procs int    `json:"procs"` // 归并了几个进程，服务维度才有意义
}

// Rank 按服务或进程统计某个时间区间内的累计流量。
//
// 历史库只存了进程维度：服务维度在查询时用 svcOf（进程名→服务名）归并，
// 而不是单独存一份。多存一份会让 agg 表体积接近翻倍，而 4GB 内存的机器上
// eMMC 写入和 DB 体积都是有预算的。
//
// 已知近似：进程退出后就不在当前快照里了，svcOf 查不到，会被算成它自己。
// 对「谁在偷跑」这个问题够用 —— 真正偷跑的服务进程通常是常驻的。
func (s *Store) Rank(rng, by string, svcOf map[string]string, limit int) ([]RankRow, error) {
	gran, span := granFor(rng)
	step := stepFor(gran)
	now := time.Now().Unix()
	end := alignBucket(now, step)
	start := end - int64(span.Seconds())

	rows, err := s.db.Query(`
SELECT key, SUM(tx), SUM(rx) FROM agg
WHERE gran=? AND dim='proc' AND bucket>=? AND bucket<=?
GROUP BY key`, gran, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	agg := map[string]*RankRow{}
	for rows.Next() {
		var k string
		var tx, rx int64
		if err := rows.Scan(&k, &tx, &rx); err != nil {
			continue
		}
		name := k
		if by == "svc" {
			if n, ok := svcOf[k]; ok && n != "" {
				name = n
			}
		}
		r := agg[name]
		if r == nil {
			r = &RankRow{Name: name}
			agg[name] = r
		}
		r.Tx += tx
		r.Rx += rx
		r.Procs++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]RankRow, 0, len(agg))
	for _, r := range agg {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Tx+out[i].Rx, out[j].Tx+out[j].Rx
		if a != b {
			return a > b
		}
		return out[i].Name < out[j].Name
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ExportRows 把历史明细直接写进 w。
//
// 不用「先拼成一个 string 再写」：24 小时的分钟级明细是 1440 × 服务数行，
// 拼字符串会让瞬时内存翻好几倍，而设备只有 4GB 内存、采集循环还在跑。
// 这里一行一行写，内存是常数级。
func (s *Store) ExportRows(w io.Writer, dim, rng string) error {
	gran, span := granFor(rng)
	now := time.Now().Unix()
	step := stepFor(gran)
	end := alignBucket(now, step)
	start := end - int64(span.Seconds())

	rows, err := s.db.Query(`
SELECT bucket, key, SUM(tx), SUM(rx) FROM agg
WHERE gran=? AND dim=? AND bucket>=? AND bucket<=?
GROUP BY bucket, key ORDER BY bucket, key`, gran, dim, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"时间", "维度", "名称", "下行字节", "上行字节", "下行MB", "上行MB"})
	for rows.Next() {
		var ts int64
		var k string
		var tx, rx int64
		if err := rows.Scan(&ts, &k, &tx, &rx); err != nil {
			continue
		}
		_ = cw.Write([]string{
			time.Unix(ts, 0).Format("2006-01-02 15:04:05"),
			dim, k,
			strconv.FormatInt(rx, 10), // 下行 = 收到的字节，和界面上的「↓」一致
			strconv.FormatInt(tx, 10),
			mb(rx), mb(tx),
		})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return cw.Error()
}

// ExportRowsSvc 是「应用」维度的明细导出：进程按服务归并、容器用容器名。
//
// 归并会让同一个 (桶, 应用) 对上多行，所以不能像 ExportRows 那样读到一行写一行。
// SQL 已经 ORDER BY bucket，同一桶的行是连续的，于是按桶缓冲、换桶时排序写出——
// 内存只有一个桶的量（30 天 1 小时粒度也就几百行），流式原则没破。
func (s *Store) ExportRowsSvc(w io.Writer, rng string, svcOf map[string]string) error {
	gran, span := granFor(rng)
	now := time.Now().Unix()
	step := stepFor(gran)
	end := alignBucket(now, step)
	start := end - int64(span.Seconds())

	rows, err := s.db.Query(`
SELECT bucket, dim, key, SUM(tx), SUM(rx) FROM agg
WHERE gran=? AND dim IN ('proc','cont') AND bucket>=? AND bucket<=?
GROUP BY bucket, dim, key ORDER BY bucket, dim, key`, gran, start, end)
	if err != nil {
		return err
	}
	defer rows.Close()

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"时间", "维度", "名称", "下行字节", "上行字节", "下行MB", "上行MB"})

	cur := int64(-1)
	acc := map[string][2]int64{} // key → {rx, tx}
	flush := func() {
		if cur < 0 || len(acc) == 0 {
			return
		}
		keys := make([]string, 0, len(acc))
		for k := range acc {
			keys = append(keys, k)
		}
		sort.Strings(keys) // 同一个桶内按名称排，导出的表才稳定可比
		for _, k := range keys {
			rx, tx := acc[k][0], acc[k][1]
			_ = cw.Write([]string{
				time.Unix(cur, 0).Format("2006-01-02 15:04:05"),
				"svc", k,
				strconv.FormatInt(rx, 10), // 下行 = 收到的字节，和界面上的「↓」一致
				strconv.FormatInt(tx, 10),
				mb(rx), mb(tx),
			})
		}
		acc = map[string][2]int64{}
	}

	for rows.Next() {
		var ts int64
		var d, k string
		var tx, rx int64
		if err := rows.Scan(&ts, &d, &k, &tx, &rx); err != nil {
			continue
		}
		if ts != cur {
			flush()
			cur = ts
		}
		out := k
		if d == "proc" {
			if v, ok := svcOf[k]; ok && v != "" {
				out = v
			}
		}
		old := acc[out]
		acc[out] = [2]int64{old[0] + rx, old[1] + tx}
	}
	flush()
	if err := rows.Err(); err != nil {
		return err
	}
	return cw.Error()
}

// ExportRank 导出区间汇总：一行一个服务（或进程），带占比，方便直接贴进表格。
//
// 和 ExportRows 的区别是「汇总 vs 明细」：看趋势用明细，写周报用这个。
func (s *Store) ExportRank(w io.Writer, rng, by string, svcOf map[string]string) error {
	rows, err := s.Rank(rng, by, svcOf, 0) // 0 = 不截断，导出的应该是全部
	if err != nil {
		return err
	}
	var total int64
	for _, r := range rows {
		total += r.Tx + r.Rx
	}
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"排名", "名称", "维度", "下行字节", "上行字节", "合计字节", "下行MB", "上行MB", "占比%"})
	for i, r := range rows {
		var pct string
		if total > 0 {
			pct = strconv.FormatFloat(float64(r.Tx+r.Rx)*100/float64(total), 'f', 2, 64)
		} else {
			pct = "0"
		}
		dim := "服务"
		if by == "proc" {
			dim = "进程"
		}
		_ = cw.Write([]string{
			strconv.Itoa(i + 1), r.Name, dim,
			strconv.FormatInt(r.Rx, 10), strconv.FormatInt(r.Tx, 10),
			strconv.FormatInt(r.Tx+r.Rx, 10),
			mb(r.Rx), mb(r.Tx), pct,
		})
	}
	return cw.Error()
}

// mb 把字节数换成保留两位的 MB 字符串，给 Excel 直接看。
func mb(n int64) string {
	return strconv.FormatFloat(float64(n)/(1024*1024), 'f', 2, 64)
}
