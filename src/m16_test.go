package main

import (
	"os"
	"path/filepath"
	"testing"
)

// 真机上的 manifest 大量写成 key="value"，不去引号界面上会显示成带引号的名字。
func TestParseManifestStripsQuotes(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		body string
		disp string
		app  string
		ok   bool
	}{
		{
			name: "双引号（真机常见）",
			body: "version=\"1.9.1-1\"\nappname=\"node_exporter\"\ndisplay_name=\"音乐\"\n",
			disp: "音乐", app: "node_exporter", ok: true,
		},
		{
			name: "单引号",
			body: "appname='trim.vm'\ndisplay_name='虚拟机'\n",
			disp: "虚拟机", app: "trim.vm", ok: true,
		},
		{
			name: "裸值（官方文档示例）",
			body: "appname=HelloFnos\ndisplay_name=Hello fnOS\n",
			disp: "Hello fnOS", app: "HelloFnos", ok: true,
		},
		{
			name: "引号里带空格",
			body: "display_name = \"  流量哨兵  \"\n",
			disp: "流量哨兵", ok: true,
		},
		{
			name: "只有 appname",
			body: "appname=\"fnnetmon\"\n",
			app:  "fnnetmon", ok: true,
		},
		{
			name: "空文件",
			body: "",
			ok:   true,
		},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "manifest"+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
		disp, app, ok := parseManifest(p)
		if disp != c.disp || app != c.app || ok != c.ok {
			t.Errorf("%s: got (%q,%q,%v) want (%q,%q,%v)",
				c.name, disp, app, ok, c.disp, c.app, c.ok)
		}
	}
}

// 软链解析后的真实路径在 @appcenter 下，只认 /var/apps 前缀会一个都匹配不上。
func TestAppPkgOf(t *testing.T) {
	cases := []struct{ exe, want string }{
		// 安装目录本身
		{"/var/apps/trim.vm/target/bin/qemu", "trim.vm"},
		// target 软链解析后的真实位置（官方应用走这条）
		{"/usr/local/apps/@appcenter/trim.photos/trim-photos", "trim.photos"},
		{"/usr/local/apps/@appcenter/fnnetmon/bin/fnnetmon", "fnnetmon"},
		// 装到存储卷上的应用
		{"/vol1/@appcenter/baidu.netdisk/target/bin/x", "baidu.netdisk"},
		{"/vol2/@appstore/plex/Plex Media Server", "plex"},
		// 不是应用
		{"/usr/sbin/sshd", ""},
		{"/usr/local/apps/@appdata/trim.photos/x", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := appPkgOf(c.exe); got != c.want {
			t.Errorf("appPkgOf(%q) = %q, want %q", c.exe, got, c.want)
		}
	}
}

// 解析 appcenter-cli list 的表格。格式按清理精灵的切法：竖线分隔，
// 第一列包名、第二列展示名，表头和分隔线要排掉。
func TestParseAppCenterList(t *testing.T) {
	out := "" +
		"APPNAME            │ DISPLAY NAME   │ VERSION\n" +
		"───────────────────┼────────────────┼─────────\n" +
		"trim.music         │ 音乐           │ 1.2.3\n" +
		"fnnetmon           │ 流量哨兵       │ 0.9.4\n" +
		"libretv            │ LibreTV 媒体库 │ 2.0.1\n" +
		"\n" +
		"共 3 个应用\n"

	got := parseAppCenterList(out)
	want := map[string]string{
		"trim.music": "音乐",
		"fnnetmon":   "流量哨兵",
		"libretv":    "LibreTV 媒体库",
	}
	if len(got) != len(want) {
		t.Fatalf("解析出 %d 条，want %d：%v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// 表头不能混进来
	if _, ok := got["APPNAME"]; ok {
		t.Errorf("表头被当成应用了：%v", got)
	}
	// 半角竖线也要认（有些终端会把全角替换掉）
	half := parseAppCenterList("trim.vm | 虚拟机 | 1.0\n")
	if half["trim.vm"] != "虚拟机" {
		t.Errorf("半角竖线解析失败：%v", half)
	}
}

// manifest 没有 display_name 时，入口配置里的 title 是第二档来源。
//
// 注意 appname 不是展示名（官方文档写的是「应用唯一标识」），
// 它等于目录名时没有任何信息量，应该让位给入口 title。
func TestLocalAppNameFallsBackToUIConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app", "ui"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := `{".url": {"demo.main": {"title": "演示应用", "icon": "images/icon_{0}.png"}}}`
	if err := os.WriteFile(filepath.Join(dir, "app", "ui", "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	// appname 和包名一样 → 等于没读到，落到入口 title
	if err := os.WriteFile(filepath.Join(dir, "manifest"),
		[]byte("appname=\"demo\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, src := localAppName(dir, "demo"); name != "演示应用" || src != "入口 title" {
		t.Errorf("appname 等于包名时应落到入口 title，得到 (%q,%q)", name, src)
	}

	// 没有入口 title 时，appname 只要和包名不同就用它
	if err := os.Remove(filepath.Join(dir, "app", "ui", "config")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"),
		[]byte("appname=\"DemoSuite\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, src := localAppName(dir, "demo"); name != "DemoSuite" || src != "appname" {
		t.Errorf("没有 title 时应用 appname，得到 (%q,%q)", name, src)
	}

	// 两个文件都没有名字 → 只剩内置表
	if err := os.WriteFile(filepath.Join(dir, "manifest"), []byte("version=1.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if name, _ := localAppName(dir, "trim.music"); name != "音乐" {
		t.Errorf("什么都没时应落到内置表，得到 %q", name)
	}
}

// 内置表要能对上 systemd 单元名和可执行文件名这两种写法。
func TestBuiltinName(t *testing.T) {
	cases := []struct{ key, want string }{
		{"trim.photos", "相册"},   // 包名原样
		{"trim-photos", "相册"},   // 可执行文件名（- 归一成 .）
		{"trim_photos", "相册"},   // 单元名写法（_ 归一成 .）
		{"TRIM.PHOTOS", "相册"},   // 大小写
		{"1Panel", "1Panel"},    // 表里是大写开头
		{"embyserver", "Emby"},  // appname 和展示名不同
		{"不存在.app", ""},         // 查不到返回空
		{"", ""},                // 空 key
		{"trim_app_center", ""}, // 内部服务不是应用
	}
	for _, c := range cases {
		if got := builtinName(c.key); got != c.want {
			t.Errorf("builtinName(%q) = %q, want %q", c.key, got, c.want)
		}
	}
}

// appcenter-cli 的名字优先级最高：本地 manifest 写错了也该以它为准。
func TestServiceIndexCenterWins(t *testing.T) {
	root := t.TempDir()
	app := filepath.Join(root, "trim.music")
	if err := os.MkdirAll(filepath.Join(app, "target", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app, "manifest"),
		[]byte("appname=trim.music\ndisplay_name=旧名字\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &ServiceIndex{root: root, names: map[string]string{}, srcOf: map[string]string{},
		center: map[string]string{"trim.music": "音乐"}}
	s.Refresh()

	exe := filepath.Join(app, "target", "bin", "trim-music")
	if got := s.Name(&ProcInfo{Exe: exe}); got != "音乐" {
		t.Errorf("应用中心的名字应该优先，得到 %q", got)
	}

	// 应用中心没有这个应用时，回到 manifest
	delete(s.center, "trim.music")
	if got := s.Name(&ProcInfo{Exe: exe}); got != "旧名字" {
		t.Errorf("应用中心没有时应回落到 manifest，得到 %q", got)
	}
}
