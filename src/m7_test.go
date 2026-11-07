package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 服务归因决定了「排行」页上那一行叫什么名字，规则错了整页就没意义。
func TestUnitName(t *testing.T) {
	cases := []struct{ cg, want string }{
		// 标准 systemd 服务
		{"/system.slice/trim-media.service", "trim-media"},
		{"/system.slice/trim-openlist.service", "trim-openlist"},
		// 服务下面挂子作用域时，取第一个 .service 段，不能取最后一段
		{"/system.slice/trim-media.service/ffmpeg.scope", "trim-media"},
		// 登录会话的 scope 不是服务，必须跳过
		{"/user.slice/user-1000.slice/session-3.scope", ""},
		// docker 的 scope 由容器分支处理，这里不认
		{"/system.slice/docker-3f2a1b4c5d6e7f80.scope", ""},
		{"", ""},
		{"/", ""},
		{"0::/system.slice/ssh.service", "ssh"},
	}
	for _, c := range cases {
		if got := unitName(c.cg); got != c.want {
			t.Errorf("unitName(%q)=%q want %q", c.cg, got, c.want)
		}
	}
}

func TestParseManifestName(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 我们自己的 fpk 就是这个结构
	full := write("m1", "appname               = fnnetmon\nversion = 0.5.0\ndisplay_name          = 流量哨兵\n")
	if got := parseManifestName(full); got != "流量哨兵" {
		t.Errorf("display_name 优先：got %q", got)
	}

	// 没有 display_name 就退回 appname
	bare := write("m2", "appname = trim.photos\nversion = 1.0\n")
	if got := parseManifestName(bare); got != "trim.photos" {
		t.Errorf("回退 appname：got %q", got)
	}

	// 注释和分节头不能当键值对解析
	odd := write("m3", "# display_name = 注释里的不算\n[section]\ndisplay_name=相册\n")
	if got := parseManifestName(odd); got != "相册" {
		t.Errorf("跳过注释：got %q", got)
	}

	if got := parseManifestName(filepath.Join(dir, "不存在")); got != "" {
		t.Errorf("文件不存在应返回空，got %q", got)
	}
}

// 可执行文件落在应用目录下时，服务名应该用应用目录的展示名。
func TestServiceIndexOfAppPath(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "trim.media")
	if err := os.MkdirAll(filepath.Join(app, "target", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "manifest"),
		[]byte("appname = trim.media\ndisplay_name = 影视\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 再放一个没有 manifest 的应用，应该退回包名
	if err := os.MkdirAll(filepath.Join(root, "bare.app"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := &ServiceIndex{root: root, names: map[string]string{}}
	s.Refresh()

	if got := s.Name(&ProcInfo{Name: "ffmpeg", Exe: filepath.Join(app, "target", "bin", "ffmpeg")}); got != "影视" {
		t.Errorf("应用目录归因：got %q want 影视", got)
	}
	if got := s.Name(&ProcInfo{Name: "x", Exe: filepath.Join(root, "bare.app", "bin", "x")}); got != "bare.app" {
		t.Errorf("无 manifest 回退包名：got %q", got)
	}
	// 不在应用目录里，退回 cgroup 单元名
	if got := s.Name(&ProcInfo{Name: "sshd", Exe: "/usr/sbin/sshd",
		Cgroup: "/system.slice/ssh.service"}); got != "ssh" {
		t.Errorf("回退 cgroup：got %q", got)
	}
	// 容器内进程返回空，由调用方用容器名
	if got := s.Name(&ProcInfo{Name: "nginx", ContainerID: "3f2a1b4c5d6e"}); got != "" {
		t.Errorf("容器内进程应返回空：got %q", got)
	}
}

// 区间排行要把同一服务下的多个进程合并成一行，并保持按总量降序。
func TestStoreRankMergesService(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()
	b := alignBucket(now-120, 60)

	rows := []AggRow{
		{Bucket: b, Gran: "1m", Dim: "proc", Key: "ffmpeg", Tx: 100, Rx: 900},
		{Bucket: b, Gran: "1m", Dim: "proc", Key: "node", Tx: 50, Rx: 450},
		{Bucket: b, Gran: "1m", Dim: "proc", Key: "baidunetdisk", Tx: 10, Rx: 5000},
		// 别的维度不该被算进来
		{Bucket: b, Gran: "1m", Dim: "total", Key: "all", Tx: 999, Rx: 999},
	}
	if err := s.Flush(rows); err != nil {
		t.Fatalf("flush: %v", err)
	}

	svcOf := map[string]string{"ffmpeg": "影视", "node": "影视", "baidunetdisk": "百度网盘"}

	got, err := s.Rank("1h", "svc", svcOf, 0)
	if err != nil {
		t.Fatalf("rank: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("应该归并成 2 个服务，got %d: %+v", len(got), got)
	}
	if got[0].Name != "百度网盘" || got[0].Tx != 10 || got[0].Rx != 5000 {
		t.Fatalf("第一行应为流量最大的百度网盘：%+v", got[0])
	}
	if got[1].Name != "影视" || got[1].Tx != 150 || got[1].Rx != 1350 || got[1].Procs != 2 {
		t.Fatalf("影视应合并两个进程：%+v", got[1])
	}

	// 按进程查时不能归并
	byProc, err := s.Rank("1h", "proc", svcOf, 0)
	if err != nil {
		t.Fatalf("rank proc: %v", err)
	}
	if len(byProc) != 3 {
		t.Fatalf("进程维度应有 3 行，got %d", len(byProc))
	}
	// 降序：百度网盘 5010 > ffmpeg 1000 > node 500
	if byProc[0].Name != "baidunetdisk" || byProc[2].Name != "node" {
		t.Fatalf("进程排序不对：%+v", byProc)
	}
}

// 区间外的数据不能被算进排行，否则「最近一小时」会混进上周的流量。
func TestStoreRankWindow(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	recent := alignBucket(now-600, 60)  // 10 分钟前：1h 和 24h 都该算
	mid := alignBucket(now-5*3600, 60)  // 5 小时前：只该算进 24h
	old := alignBucket(now-30*3600, 60) // 30 小时前：两个窗口都不该算

	if err := s.Flush([]AggRow{
		{Bucket: recent, Gran: "1m", Dim: "proc", Key: "a", Tx: 1, Rx: 1},
		{Bucket: mid, Gran: "1m", Dim: "proc", Key: "b", Tx: 10, Rx: 10},
		{Bucket: old, Gran: "1m", Dim: "proc", Key: "c", Tx: 100, Rx: 100},
	}); err != nil {
		t.Fatalf("flush: %v", err)
	}

	got, err := s.Rank("1h", "svc", nil, 0)
	if err != nil {
		t.Fatalf("rank: %v", err)
	}
	if len(got) != 1 || got[0].Name != "a" {
		t.Fatalf("1 小时窗口只应包含 a：%+v", got)
	}

	got, err = s.Rank("24h", "svc", nil, 0)
	if err != nil {
		t.Fatalf("rank: %v", err)
	}
	if len(got) != 2 || got[0].Name != "b" || got[1].Name != "a" {
		t.Fatalf("24 小时窗口应包含 a 和 b（b 在前）：%+v", got)
	}
}
