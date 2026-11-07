package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

// 热加载：装完 City 库不重启进程也能生效。
//
// 这条路径只在界面上点「安装省市数据」时走到，CLI 走的是「装完提示重启」，
// 所以没有测试的话，最容易漏的反而是最常被点的那条。
func TestGeoReloadPicksUpCity(t *testing.T) {
	src := filepath.Join("..", "data", "geo")
	city := filepath.Join(src, "GeoLite2-City.mmdb")
	country := filepath.Join(src, "GeoLite2-Country.mmdb")
	asn := filepath.Join(src, "GeoLite2-ASN.mmdb")
	for _, f := range []string{city, country, asn} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("缺少 %s，跳过（只有构建机上有完整库）", filepath.Base(f))
		}
	}

	dataDir := t.TempDir()    // 模拟 <var>/geo
	builtinDir := t.TempDir() // 模拟程序目录里的内置库（这里故意留空）
	copyFileT(t, country, filepath.Join(dataDir, "GeoLite2-Country.mmdb"))
	copyFileT(t, asn, filepath.Join(dataDir, "GeoLite2-ASN.mmdb"))

	g := OpenGeo(dataDir, builtinDir)
	defer g.Close()
	if !g.Available() {
		t.Fatal("应该能加载到国家库")
	}
	if st := g.Status(); st.City {
		t.Fatal("还没装 City，不该报有城市级")
	}

	copyFileT(t, city, filepath.Join(dataDir, "GeoLite2-City.mmdb"))
	if err := g.Reload(); err != nil {
		t.Fatalf("热加载失败：%v", err)
	}

	st := g.Status()
	if !st.City {
		t.Fatal("装上 City 后应该报有城市级")
	}
	if st.Source != "数据目录" {
		t.Fatalf("来源应为「数据目录」，实际 %q", st.Source)
	}
	// 断言用的 IP 必须从库里现取：GeoLite2 里绝大多数地址（包括 8.8.8.8）
	// 只有国家、没有 city / subdivisions，写死一个公网 IP 就是在赌它恰好有城市数据，
	// 换一版库就会挂。这里扫出第一个确实带 city 的网段，用它的首地址。
	sample := citySampleIP(t, city)
	if gi := g.Lookup(sample); gi.City == "" || gi.Region == "" {
		t.Fatalf("City 库查 %s 应该能拿到省和市，实际 %+v", sample, gi)
	}
}

// 删掉 City 库再热加载，应该干净地退回国家 + ASN，不能残留旧的省市级状态。
func TestGeoReloadAfterRemove(t *testing.T) {
	src := filepath.Join("..", "data", "geo")
	city := filepath.Join(src, "GeoLite2-City.mmdb")
	country := filepath.Join(src, "GeoLite2-Country.mmdb")
	for _, f := range []string{city, country} {
		if _, err := os.Stat(f); err != nil {
			t.Skipf("缺少 %s，跳过", filepath.Base(f))
		}
	}

	dataDir := t.TempDir()
	builtinDir := t.TempDir()
	copyFileT(t, city, filepath.Join(dataDir, "GeoLite2-City.mmdb"))
	copyFileT(t, country, filepath.Join(builtinDir, "GeoLite2-Country.mmdb"))

	g := OpenGeo(dataDir, builtinDir)
	defer g.Close()
	if !g.Status().City {
		t.Fatal("数据目录里有 City，应该用 City")
	}
	sample := citySampleIP(t, city)
	if gi := g.Lookup(sample); gi.City == "" {
		t.Fatalf("删库前 %s 应该有城市名，实际 %+v", sample, gi)
	}

	if err := removeGeoCity(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := g.Reload(); err != nil {
		t.Fatalf("删除后热加载失败：%v", err)
	}
	st := g.Status()
	if st.City {
		t.Fatal("删掉 City 后不该还报有城市级")
	}
	if !st.Available {
		t.Fatal("内置国家库还在，不该变成「不可用」")
	}
	if st.Source != "内置" {
		t.Fatalf("来源应回落到「内置」，实际 %q", st.Source)
	}
	// 缓存必须清掉，否则旧库里查到的城市名会跟着新库一起显示
	if gi := g.Lookup(sample); gi.City != "" || gi.Region != "" {
		t.Fatalf("换库后不该还留着旧的省市名：%+v", gi)
	}
}

// citySampleIP 从 City 库里扫出第一个带城市数据的网段，返回它的首地址。
//
// 不用固定的公网 IP：GeoLite2-City 里大量地址（8.8.8.8 就是）只到国家级，
// 写死会让测试在换库后莫名其妙地挂掉，而失败信息完全看不出是数据的问题。
func citySampleIP(t *testing.T, dbPath string) string {
	t.Helper()
	r, err := maxminddb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	it := r.Networks(maxminddb.SkipAliasedNetworks)
	for it.Next() {
		var raw map[string]any
		nw, err := it.Network(&raw)
		if err != nil {
			t.Fatal(err)
		}
		if raw["city"] != nil && raw["subdivisions"] != nil && nw.IP != nil {
			return nw.IP.String()
		}
	}
	t.Fatal("整库找不到带 city 的网段，库文件可能不完整")
	return ""
}

// 一个库都没有时 Reload 要报错，而不是静默把状态清空——
// 界面要靠这个错误告诉用户「装是装上了，但加载失败」。
func TestGeoReloadNoDatabase(t *testing.T) {
	dir := t.TempDir()
	g := OpenGeo(dir)
	defer g.Close()
	if err := g.Reload(); err == nil {
		t.Fatal("空目录应该返回错误")
	}
}

func copyFileT(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
