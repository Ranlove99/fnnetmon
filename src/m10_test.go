package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// 连接和外联页都要显示应用名（svc）。前端整页依赖这个 JSON 契约，
// ProcAgg 曾经漏写 tag 导致前端整页 undefined——所以这里把字段名锁死。
func TestSvcJSONContract(t *testing.T) {
	cv, err := json.Marshal(ConnView{Proc: "trim_media", Svc: "飞牛影视"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(cv, &m); err != nil {
		t.Fatal(err)
	}
	if m["svc"] != "飞牛影视" {
		t.Errorf("ConnView 的应用名字段必须是 svc，得到 %v", m["svc"])
	}

	// Peer 的 svc 不落库（UpsertPeers 列是显式的），且为空时不出现在 JSON 里，
	// 老记录（peer 表里没有应用名概念）不会因此多出空字段。
	p, err := json.Marshal(Peer{Proc: "trim_media", Svc: "飞牛影视"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(p), `"svc":"飞牛影视"`) {
		t.Errorf("Peer 的应用名字段必须是 svc：%s", p)
	}
	empty, err := json.Marshal(Peer{Proc: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "svc") {
		t.Errorf("svc 为空时应该被 omitempty 掉：%s", empty)
	}
}

// 服务归因的三级优先：应用目录 > systemd 单元 > 可执行文件名。
// 应用目录命中时返回的是 display_name（用户在桌面上看到的那个名字），
// 连接页拿它当主标题，所以这里顺带验证返回的是展示名而不是包名。
func TestServiceIndexPriority(t *testing.T) {
	s := NewServiceIndex()

	// 应用目录：exe 落在 /var/apps/<pkg>/app/bin 下，names 里是展示名。
	s.root = "/var/apps"
	s.names = map[string]string{"trim-media": "飞牛影视"}
	if pkg := appPkgOf("/var/apps/trim-media/app/bin/trim_media"); pkg != "trim-media" {
		t.Errorf("应从 exe 路径取出包名 trim-media，得到 %q", pkg)
	}
	if got := s.Name(&ProcInfo{Exe: "/var/apps/trim-media/app/bin/trim_media"}); got != "飞牛影视" {
		t.Errorf("应用目录命中应返回展示名，得到 %q", got)
	}

	// systemd 单元：不在应用目录下的 exe 走 cgroup 里第一个 .service。
	info := &ProcInfo{Name: "worker", Exe: "/usr/bin/worker",
		Cgroup: "/system.slice/trim-sync.service/app.slice/worker.scope"}
	if u := unitName(info.Cgroup); u != "trim-sync" {
		t.Errorf("单元名应取第一个 .service 段，得到 %q", u)
	}
	if n := s.Name(info); n != "trim-sync" {
		t.Errorf("非应用进程应归到 systemd 单元名，得到 %q", n)
	}

	// 两个兜底：无应用无单元时用可执行文件名，最后才是 comm。
	info2 := &ProcInfo{Name: "worker", Exe: "/opt/tools/collector"}
	if n := s.Name(info2); n != "collector" {
		t.Errorf("无单元时应退到可执行文件名，得到 %q", n)
	}
	info3 := &ProcInfo{Name: "kworker/u8:2"}
	if n := s.Name(info3); n != "kworker/u8:2" {
		t.Errorf("什么都没有时退到 comm，得到 %q", n)
	}
}
