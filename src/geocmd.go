package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// 地理库按需安装。
//
// 包体积和「有省市」是互斥的：City 库原始 48MB，fpk 外层已经 gzip 过，
// 再预压一遍毫无意义（实测仍占 25MB）。所以基础包只带 Country + ASN（11.5MB），
// City 变成「想要就装」的可选项——装一次落在数据目录里，以后升级 fpk 也不会被覆盖。
//
// 三个入口：
//
//	geo status            现在加载了什么、City 有没有
//	geo install <file>    本地已有 mmdb，直接装
//	geo fetch             从网络拉 City（默认走 ghproxy 镜像）
const (
	geoCityFile = "GeoLite2-City.mmdb"
	// MaxMind 官方下载要 license key，GitHub 直连在国内常被拦，用镜像。
	geoCityURL = "https://ghproxy.net/https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb"
)

func runGeo(args []string) {
	// -var 允许写在任意位置：flag 包遇到第一个非选项参数就停止解析，
	// 而用户自然会写成 `geo install 文件 -var /tmp/x`，得自己扫一遍。
	var varDir string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-var" || a == "--var":
			if i+1 < len(args) {
				varDir = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-var=") || strings.HasPrefix(a, "--var="):
			varDir = a[strings.IndexByte(a, '=')+1:]
		default:
			rest = append(rest, a)
		}
	}
	args = rest
	dir := resolveVarDir(varDir)
	installDir := filepath.Join(dir, "geo")

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fnnetmon geo <status|install <file.mmdb>|fetch|remove>")
		os.Exit(1)
	}

	switch args[0] {
	case "status":
		geo := OpenGeo(geoDirs(dir)...)
		defer geo.Close()
		st := geo.Status()
		fmt.Printf("数据目录: %s\n", st.Dir)
		if !st.Available {
			fmt.Println("当前状态: 没有可用的库（国家和运营方都不显示）")
			if st.Error != "" {
				fmt.Printf("错误: %s\n", st.Error)
			}
		} else {
			fmt.Printf("当前状态: %s · %s\n", strings.Join(st.Files, " + "), st.Source)
			if st.Build != "" {
				fmt.Printf("数据构建: %s\n", st.Build)
			}
			if st.City {
				fmt.Println("城市级:   有（省 / 市会显示在悬停提示里）")
			} else {
				fmt.Println("城市级:   没有（只有国家 + 运营方）")
			}
		}
		fmt.Println()
		if st.City {
			fmt.Println("换新库：把 mmdb 覆盖到 " + installDir + " 即可")
		} else {
			fmt.Println("想要省市：fnnetmon geo fetch（联网下载 48MB）")
			fmt.Println("或者把 GeoLite2-City.mmdb 放进 " + installDir)
		}

	case "install":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "usage: fnnetmon geo install <path/to/GeoLite2-City.mmdb>")
			os.Exit(1)
		}
		if err := geoInstall(args[1], installDir); err != nil {
			fmt.Fprintf(os.Stderr, "安装失败：%v\n", err)
			os.Exit(1)
		}
		fmt.Println("已安装，重启应用后生效：")
		fmt.Println("  应用中心里停一次再启动，或 systemctl restart fnnetmon")

	case "fetch":
		if err := geoFetch(installDir); err != nil {
			fmt.Fprintf(os.Stderr, "\n下载失败：%v\n", err)
			fmt.Fprintln(os.Stderr, "可以手动下载后执行：fnnetmon geo install <文件>")
			os.Exit(1)
		}
		fmt.Println("\n已安装，重启应用后生效：")
		fmt.Println("  应用中心里停一次再启动，或 systemctl restart fnnetmon")
		fmt.Println("  （在界面上点「安装省市数据」不需要重启，会直接热加载）")

	case "remove":
		if err := removeGeoCity(installDir); err != nil {
			fmt.Fprintf(os.Stderr, "删除失败：%v\n", err)
			os.Exit(1)
		}
		fmt.Println("已删除 City 库（国家 + 运营方不受影响），重启应用后生效")

	default:
		fmt.Fprintf(os.Stderr, "unknown geo action: %s\n", args[0])
		os.Exit(1)
	}
}

// geoInstall 校验并安装一个 mmdb。
// 先写到同目录的临时文件再 rename：中途断电不会留下半个库，
// 否则 maxminddb 打开时读到截断数据会直接报错，用户以为装坏了。
func geoInstall(src, installDir string) error {
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	// 先确认这确实是个能打开的 mmdb，别把随便什么文件拷进去
	r, err := maxminddb.Open(src)
	if err != nil {
		return fmt.Errorf("不是有效的 mmdb：%v", firstLine(err.Error()))
	}
	typ := r.Metadata.DatabaseType
	_ = r.Close()
	if !strings.Contains(strings.ToLower(typ), "city") &&
		!strings.Contains(strings.ToLower(typ), "country") &&
		!strings.Contains(strings.ToLower(typ), "asn") {
		return fmt.Errorf("库类型不认识：%s", typ)
	}

	name := filepath.Base(src)
	if strings.Contains(strings.ToLower(typ), "city") {
		name = geoCityFile
	}
	dst := filepath.Join(installDir, name)
	tmp := dst + ".tmp"

	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	fmt.Printf("已安装 %s（%s）\n", name, humanSize(fileSize(dst)))
	return nil
}

// geoFetch 从镜像拉 City 库。48MB，超时给足 10 分钟——
// 小水管设备上 600 秒确实不够（之前就吃过一次 SIGTERM）。
//
// 进度通过 onProgress 回调出去：CLI 打到 stdout，HTTP 那边写进任务状态。
// 两边共用同一段下载逻辑，免得「命令行能装、界面上装不上」这种分裂。
func geoFetch(installDir string) error {
	return geoFetchTo(installDir, func(done, total int64) {
		if total > 0 {
			fmt.Printf("\r  %5.1f / %.1f MB  (%d%%)", float64(done)/(1<<20),
				float64(total)/(1<<20), done*100/total)
		} else {
			fmt.Printf("\r  %.1f MB", float64(done)/(1<<20))
		}
	})
}

func geoFetchTo(installDir string, onProgress func(done, total int64)) error {
	if err := os.MkdirAll(installDir, 0o755); err != nil {
		return err
	}
	url := os.Getenv("FNNETMON_GEO_URL")
	if url == "" {
		url = geoCityURL
	}
	cli := &http.Client{Timeout: 10 * time.Minute}
	resp, err := cli.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	dst := filepath.Join(installDir, geoCityFile)
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	// 边下边报进度：48MB 在慢速设备上要几分钟，没有反馈用户会以为卡死
	pr := &progressReader{r: resp.Body, total: resp.ContentLength, last: time.Now(), on: onProgress}
	n, err := io.Copy(out, pr)
	if err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	out.Close()
	if onProgress != nil {
		onProgress(n, n)
	}

	// 下载下来的东西必须能当 mmdb 打开，否则是镜像返回了错误页
	r, err := maxminddb.Open(tmp)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("文件校验失败（可能下到了错误页）：%v", firstLine(err.Error()))
	}
	typ := r.Metadata.DatabaseType
	_ = r.Close()
	if !strings.Contains(strings.ToLower(typ), "city") {
		os.Remove(tmp)
		return fmt.Errorf("库类型不对：%s", typ)
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

type progressReader struct {
	r     io.Reader
	total int64
	read  int64
	last  time.Time
	on    func(done, total int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.read += int64(n)
	if time.Since(p.last) > 2*time.Second && p.on != nil {
		p.last = time.Now()
		p.on(p.read, p.total)
	}
	return n, err
}

func fileSize(p string) int64 {
	if st, err := os.Stat(p); err == nil {
		return st.Size()
	}
	return 0
}

// removeGeoCity 删掉数据目录里的 City 库。
// 只删这一个文件：国家库和 ASN 库在程序目录里，不该被这里动到。
func removeGeoCity(installDir string) error {
	p := filepath.Join(installDir, geoCityFile)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
