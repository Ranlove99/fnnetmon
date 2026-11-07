package main

import (
	"os"
	"path/filepath"
	"testing"
)

// manifest 解析有四种结果，它们回落到不同的名字。
// 核对工具（fnnetmon svc）靠这个区分「该改哪里」——
// 只看最终名字分不出是文件没了、还是少写一行 display_name。
func TestParseManifestSources(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		file    string
		wantD   string // display_name
		wantA   string // appname
		wantOK  bool   // 文件在不在
		comment string
	}{
		{write("full", "appname = trim.media\ndisplay_name = 飞牛影视\n"), "飞牛影视", "trim.media", true,
			"两个都有，display_name 优先"},
		{write("onlyapp", "appname = baidunetdisk\nversion = 1.0\n"), "", "baidunetdisk", true,
			"只有 appname，回落到它"},
		{write("neither", "[meta]\nversion = 2\n"), "", "", true,
			"文件在但两个键都没有，回落到包名"},
		{filepath.Join(dir, "nofile"), "", "", false, "文件不存在"},
		{write("spaces", "  display_name   =   带空格的   \n"), "带空格的", "", true,
			"键和值两边的空格要 trim 掉，否则界面上名字带空格"},
		{write("comment", "# display_name = 注释里的不算\nappname = real\n"), "", "real", true,
			"注释行不能被当成配置"},
	}

	for _, c := range cases {
		d, a, ok := parseManifest(c.file)
		if d != c.wantD || a != c.wantA || ok != c.wantOK {
			t.Errorf("%s：got (%q, %q, %v)，want (%q, %q, %v)",
				c.comment, d, a, ok, c.wantD, c.wantA, c.wantOK)
		}
	}
}

// parseManifestName 是给 ServiceIndex 用的简版：它只要最终名字。
// 这条断言防止以后改 parseManifest 时把回落顺序弄反。
func TestParseManifestNameFallback(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		body string
		want string
	}{
		{"display_name = 飞牛影视\nappname = x\n", "飞牛影视"},
		{"appname = baidunetdisk\n", "baidunetdisk"},
		{"[meta]\nversion = 1\n", ""},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "m"+string(rune('a'+i)))
		if err := os.WriteFile(p, []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := parseManifestName(p); got != c.want {
			t.Errorf("parseManifestName(%q) = %q, want %q", c.body, got, c.want)
		}
	}
}

// 核对表要按包名排序：真机上几十个应用，顺序乱跳没法逐行对。
func TestScanAppsSorted(t *testing.T) {
	root := t.TempDir()
	for _, pkg := range []string{"z.app", "a.app", "m.app"} {
		d := filepath.Join(root, pkg)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "manifest"), []byte("display_name = "+pkg+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 混一个普通文件进去，不能被当成应用
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := scanApps(root, nil)
	if len(got) != 3 {
		t.Fatalf("应用数 = %d, want 3：%+v", len(got), got)
	}
	want := []string{"a.app", "m.app", "z.app"}
	for i, w := range want {
		if got[i].Pkg != w {
			t.Fatalf("第 %d 个是 %q, want %q", i, got[i].Pkg, w)
		}
		if got[i].Source != "display_name" {
			t.Fatalf("%s 的 source = %q, want display_name", w, got[i].Source)
		}
	}
}

// 中文字符占两格，用 rune 数补空格会让表格错位。
func TestPadDisplayWidth(t *testing.T) {
	if got := displayWidth("飞牛影视"); got != 8 {
		t.Fatalf("4 个汉字应算 8 格，实际 %d", got)
	}
	if got := displayWidth("abcd"); got != 4 {
		t.Fatalf("4 个 ASCII 应算 4 格，实际 %d", got)
	}
	// 补到同一个宽度后，显示宽度必须一致——这才是表格能对齐的条件
	a, b := pad("飞牛影视", 12), pad("abcdefgh", 12)
	if displayWidth(a) != displayWidth(b) {
		t.Fatalf("补空格后显示宽度不一致：%q=%d vs %q=%d",
			a, displayWidth(a), b, displayWidth(b))
	}
}
