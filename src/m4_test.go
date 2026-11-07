package main

import (
	"fmt"
	"testing"
	"time"
)

// procTot 只增不减会慢慢变胖，pruneTotals 必须能清掉僵尸条目，
// 同时不能误删还在跑的。
func TestPruneTotals(t *testing.T) {
	h := NewHub()
	h.procTot["gone"] = &ProcAgg{Key: "gone", seen: time.Now().Add(-7 * time.Hour)}
	h.procTot["recent"] = &ProcAgg{Key: "recent", seen: time.Now().Add(-2 * time.Minute)}
	h.procTot["never"] = &ProcAgg{Key: "never"} // seen 为零值，不该被误删
	h.contTot["oldcont"] = &ProcAgg{Key: "oldcont", seen: time.Now().Add(-7 * time.Hour)}

	h.pruneTotals(time.Now())

	if _, ok := h.procTot["gone"]; ok {
		t.Error("7 小时没出现的进程应被清理")
	}
	if _, ok := h.procTot["recent"]; !ok {
		t.Error("2 分钟前还活跃的进程不该被清理")
	}
	if _, ok := h.procTot["never"]; !ok {
		t.Error("seen 为零值的条目不该被清理（可能是刚初始化）")
	}
	if _, ok := h.contTot["oldcont"]; ok {
		t.Error("陈旧的容器条目应被清理")
	}
}

// 对端表必须有上限，否则一个扫描器跑一晚就能把内存吃光。
func TestPeerMaxKeep(t *testing.T) {
	tr := NewPeerTracker(nil)
	tr.maxKeep = 10
	for i := 0; i < 50; i++ {
		tr.Observe(obs("p", "", "/c", fmt.Sprintf("203.0.113.%d", i), 443, "tcp", true, 0, 0))
		// First 时间戳都相同的话排序不稳定，这里错开一点
		time.Sleep(time.Millisecond)
	}
	tr.Flush()
	if n := tr.Count(); n > 10 {
		t.Fatalf("超过 maxKeep 后应淘汰到 10 条，得到 %d", n)
	}
	if n := tr.Count(); n == 0 {
		t.Fatal("不该把条目全删光")
	}
}

// tick 统计要能反映采集是否还活着——这是「页面不更新」类故障的第一判据。
func TestTickStats(t *testing.T) {
	h := NewHub()
	h.tick()
	h.tick()
	st := h.stats()
	if st.Ticks != 2 {
		t.Errorf("tick 计数应为 2，得到 %d", st.Ticks)
	}
	if st.IdleSec > 5 {
		t.Errorf("刚 tick 过，idle 不该超过 5 秒，得到 %d", st.IdleSec)
	}
	if st.MaxMs < st.LastMs {
		t.Errorf("最慢耗时 %.2f 不该小于最近耗时 %.2f", st.MaxMs, st.LastMs)
	}
}

// 自检本身不能因为某个子系统缺失就崩掉：这是排障工具的基本要求。
func TestSelfCheckWithoutSubsystems(t *testing.T) {
	sc := BuildSelfCheck(nil, nil, nil, nil)
	if sc.Version == "" {
		t.Error("应带上版本号")
	}
	if sc.Verdict == "" {
		t.Error("应给出结论")
	}
	// 没有 store 时应明确告警，而不是假装正常
	found := false
	for _, c := range sc.Checks {
		if c.Name == "数据库" && c.Level != "ok" {
			found = true
		}
	}
	if !found {
		t.Error("数据库不可用时应该出现在检查项里并标为非 ok")
	}
	if sc.Text() == "" {
		t.Error("文本输出不该为空")
	}
}

func TestSelfCheckWithStore(t *testing.T) {
	s := newTestStore(t)
	defer s.Close()

	sc := BuildSelfCheck(nil, s, nil, nil)
	if !sc.Storage.OK {
		t.Fatal("有 store 时 Storage.OK 应为 true")
	}
	if sc.Storage.Path == "" {
		t.Error("应带上数据库路径，方便用户直接去看文件")
	}
}

// 中文标签的宽度计算：一个汉字算 2 列，否则表格会歪。
func TestPadRightWidth(t *testing.T) {
	if got := padRight("RSS", 16); len(got) != 16 {
		t.Errorf("ASCII 补到 16 字节，得到 %d", len(got))
	}
	// "文件描述符" = 5 个汉字 = 10 列，应补 6 个空格
	got := padRight("文件描述符", 16)
	if len(got) != len("文件描述符")+6 {
		t.Errorf("中文应按显示宽度补空格，得到 %q", got)
	}
}
