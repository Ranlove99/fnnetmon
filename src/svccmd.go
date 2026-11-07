package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// runSvc 打印「应用包名 → 展示名」的对照表，用来在真机上核对服务名。
//
// 名字的来源有四个（见 ServiceIndex 的注释），前三个都要在真机上才读得到。
// 一旦某个环节读不出来，名字会悄悄回落到下一档，界面上只显示成 trim.xxx
// 而不报错——所以需要一条命令把「每个应用实际解析出什么、依据是哪一行」列出来。
//
// 用法：fnnetmon svc [--json] [--root /var/apps] [--no-cli]
func runSvc(args []string) {
	fs := flag.NewFlagSet("svc", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "输出 JSON（方便贴给别人看）")
	root := fs.String("root", "", "指定应用根目录（默认自动探测 /var/apps、/usr/trim/apps）")
	noCLI := fs.Bool("no-cli", false, "不调用 appcenter-cli，只看本地文件")
	fs.Parse(args)

	roots := appRoots
	if *root != "" {
		roots = []string{*root}
	}

	hitRoot := ""
	for _, r := range roots {
		if st, err := os.Stat(r); err == nil && st.IsDir() {
			hitRoot = r
			break
		}
	}

	// 应用中心那条来源单独拿：它给的是「已装应用」的权威名字，
	// 和本地 manifest 对照着看，才能发现哪一边写错了。
	center := map[string]string{}
	cliNote := ""
	if !*noCLI {
		out, err := runAppCenterList()
		if err != nil {
			cliNote = err.Error()
		} else if m := parseAppCenterList(out); len(m) > 0 {
			center = m
		} else {
			cliNote = "appcenter-cli list 输出无法解析（0 行）"
		}
	}

	if hitRoot == "" && len(center) == 0 {
		fmt.Fprintf(os.Stderr, "没有找到应用目录（试过 %s）。\n", strings.Join(roots, "、"))
		if cliNote != "" {
			fmt.Fprintf(os.Stderr, "应用中心也读不到：%s\n", cliNote)
		}
		fmt.Fprintf(os.Stderr, "这个命令要在 fnOS 真机上跑；开发机上没有 /var/apps 是正常的。\n")
		os.Exit(1)
	}

	entries := scanApps(hitRoot, center)
	if *asJSON {
		out := map[string]any{
			"root":      hitRoot,
			"appcenter": center,
			"cli_note":  cliNote,
			"apps":      entries,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return
	}

	if hitRoot != "" {
		fmt.Printf("应用根目录 %s（%d 个应用）\n", hitRoot, len(entries))
	} else {
		fmt.Printf("没有应用目录，只列出应用中心报告的 %d 个应用\n", len(entries))
	}
	switch {
	case cliNote != "":
		fmt.Printf("应用中心：读不到（%s）\n\n", cliNote)
	case len(center) > 0:
		fmt.Printf("应用中心：%d 个已装应用\n\n", len(center))
	}
	if len(entries) == 0 {
		fmt.Printf("没有可核对的应用。\n")
		return
	}

	needCheck, mismatch := 0, 0
	fmt.Printf("  %s%s%s%s\n", pad("包名", 30), pad("本地读到的名字", 24), pad("依据", 16), "应用中心")
	for _, e := range entries {
		mark := ""
		if e.Source != "display_name" {
			mark = "  ⚠"
			needCheck++
		}
		cli := e.Center
		if cli == "" {
			cli = "-"
		} else if e.Name != "" && cli != e.Name {
			// 两边都读到了但不一样：说明本地那个 manifest 写错了，或者应用中心
			// 的显示名改过没同步。这行才是真正要看的。
			cli += "  ≠"
			mismatch++
		}
		name := e.Name
		if name == "" {
			name = "（空）"
		}
		fmt.Printf("  %s%s%s%s%s\n", pad(e.Pkg, 30), pad(name, 24), pad(e.Source, 16), pad(cli, 20), mark)
	}

	fmt.Printf("\n")
	if needCheck == 0 && mismatch == 0 {
		fmt.Printf("全部 %d 个应用的名字都来自 display_name，且和应用中心一致。\n", len(entries))
		return
	}
	if needCheck > 0 {
		fmt.Printf("%d 个应用的名字不是从 display_name 读出来的（标 ⚠ 的行）：\n", needCheck)
		fmt.Printf("  - 「缺 manifest」：目录里没有 manifest 文件\n")
		fmt.Printf("  - 「manifest 无名字」：有文件但没有 display_name / appname\n")
		fmt.Printf("  - 「入口 title」：从 app/ui/config 的 title 读到的\n")
		fmt.Printf("  - 「内置表」：本地什么都读不到，用了打包时内置的对照表\n")
	}
	if mismatch > 0 {
		fmt.Printf("%d 个应用本地名字和应用中心不一致（标 ≠ 的行）：manifest 该改了。\n", mismatch)
	}
	fmt.Printf("\n这几行就是界面上可能显示成 trim.xxx 或者进程名的地方。\n")
	fmt.Printf("加 `--json` 可以输出结构化结果，方便贴出来。\n")
}

// svcEntry 是一个应用的核对结果。
type svcEntry struct {
	Pkg    string `json:"pkg"`              // 应用包名（/var/apps 下的目录名）
	Name   string `json:"name"`             // 本地文件里读到的名字
	Source string `json:"source"`           // display_name / appname / 入口 title / 内置表 / 缺 manifest
	Center string `json:"center,omitempty"` // appcenter-cli 报告的名字
}

// scanApps 读应用目录下每个应用的元数据，按包名排序返回。
//
// center 是 appcenter-cli 的结果；应用中心里有、本地目录里没有的应用也要列出来
// （那种情况说明 /var/apps 少了一半，是另一个问题）。
func scanApps(root string, center map[string]string) []svcEntry {
	seen := map[string]bool{}
	out := make([]svcEntry, 0, len(center)+8)

	if root != "" {
		if ents, err := os.ReadDir(root); err == nil {
			for _, e := range ents {
				if !e.IsDir() {
					continue
				}
				pkg := e.Name()
				name, src := localAppName(filepath.Join(root, pkg), pkg)
				if name == "" {
					name = pkg
				}
				out = append(out, svcEntry{Pkg: pkg, Name: name, Source: src, Center: center[pkg]})
				seen[pkg] = true
			}
		}
	}

	// 应用中心有、本地没有的，也列出来并标清楚
	for pkg, name := range center {
		if seen[pkg] {
			continue
		}
		out = append(out, svcEntry{Pkg: pkg, Name: "", Source: "本地无目录", Center: name})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Pkg < out[j].Pkg })
	return out
}

// pad 按显示宽度右补空格。中文占两格，用 rune 数会错位。
func pad(s string, w int) string {
	n := w - displayWidth(s)
	if n <= 0 {
		return s
	}
	return s + strings.Repeat(" ", n)
}

func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		if r > 0x2E80 { // 中日韩字符大致从这里开始占两格
			w += 2
		} else {
			w++
		}
	}
	return w
}
