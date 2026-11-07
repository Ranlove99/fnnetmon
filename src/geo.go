package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// 内置的地理/ASN 数据。
//
// GeoLite2 以 CC BY-SA 4.0 发布，允许再分发，前提是署名并以相同许可共享
// （见数据目录里的 NOTICE.txt）。所以直接打进 fpk，装上就能用，
// 不用用户自己去 MaxMind 注册账号、申请 license key、再手工丢文件。
//
// 扫描顺序：数据目录在前、内置目录在后。用户想换新库，把 mmdb 丢进数据目录即可，
// 不用重新打包；同一个目录里 City 优先于 Country（City 是 Country 的超集）。

type GeoInfo struct {
	CC     string `json:"cc,omitempty"`     // 国家代码
	Name   string `json:"cn,omitempty"`     // 国家名（优先中文）
	Region string `json:"region,omitempty"` // 一级行政区，City 库才有
	City   string `json:"city,omitempty"`   // 城市，City 库才有
	ASN    uint   `json:"asn,omitempty"`    // 自治系统号
	Org    string `json:"org,omitempty"`    // ASN 组织名
}

func (g GeoInfo) Empty() bool { return g.CC == "" && g.ASN == 0 }

// mmPlace 同时兼容 Country 和 City 两种库：Country 库里没有 city / subdivisions，
// 解出来是零值，不影响。
type mmPlace struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
}

type mmASN struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

type GeoDB struct {
	mu     sync.RWMutex
	place  *maxminddb.Reader // City 或 Country
	asn    *maxminddb.Reader
	cache  map[string]GeoInfo
	files  []string
	dirs   []string
	source string // 地理库来自哪个目录，给界面显示
	city   bool
	build  string
	loaded bool
	err    string
	// builtin 是内置库目录（搜索顺序的最后一项）。判断「来源」时拿它比对，
	// 不能拿 dirs[0]——数据目录有 geo/ 和根目录两种放法，都会被当成内置。
	builtin string
}

const maxGeoCache = 8192

// geoDirs 返回 mmdb 的搜索目录，按优先级排列：
//
//	<数据目录>/geo   ← 推荐位置（geo install/fetch 就装这里，升级 fpk 不会覆盖）
//	<数据目录>       ← 老位置，早期版本让人直接丢这儿，继续支持
//	<可执行文件>/geo ← 内置库（基础包只带 Country + ASN）
//
// 用 os.Executable 而不是写死 /var/apps/fnnetmon：升级会换目录，也可能装到别处。
func geoDirs(varDir string) []string {
	out := []string{filepath.Join(varDir, "geo"), varDir}
	exe, err := os.Executable()
	if err != nil {
		return out
	}
	if p, err := filepath.EvalSymlinks(exe); err == nil {
		exe = p
	}
	return append(out, filepath.Join(filepath.Dir(exe), "geo"))
}

// OpenGeo 按顺序扫描若干目录里的 mmdb，先找到的目录优先。
// 一个都找不到不算错，只是不显示地理信息。
func OpenGeo(dirs ...string) *GeoDB {
	g := &GeoDB{cache: map[string]GeoInfo{}, dirs: dirs}
	if len(dirs) > 0 {
		g.builtin = dirs[len(dirs)-1]
	}
	place, asn, errMsg := geoScan(dirs)
	g.err = errMsg
	g.apply(place, asn)
	return g
}

// geoPick 是一次扫描里选中的库。
type geoPick struct {
	r    *maxminddb.Reader
	name string
	dir  string
	rank int
}

// geoScan 在目录列表里挑出最合适的地理库和 ASN 库。
// 抽出来是因为「装完 City 库要热加载」也要走同一套挑选逻辑，
// 不能 OpenGeo 一套、Reload 另一套，否则两边优先级会悄悄走样。
func geoScan(dirs []string) (place, asn *geoPick, errMsg string) {
	// rank 越大越优先：目录顺序决定优先级，同目录内 City 高于 Country。
	// 用户往数据目录里放了一个 Country 库，就说明他想要那个，不能被内置的 City 顶掉。
	base := len(dirs) + 1

	for di, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		dirRank := (base - di) * 10
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".mmdb") {
				continue
			}
			r, err := maxminddb.Open(filepath.Join(dir, e.Name()))
			if err != nil {
				errMsg = "打开 " + e.Name() + " 失败：" + firstLine(err.Error())
				continue
			}
			t := strings.ToLower(r.Metadata.DatabaseType)
			switch {
			case strings.Contains(t, "asn"):
				if asn == nil || dirRank+1 > asn.rank {
					if asn != nil {
						_ = asn.r.Close()
					}
					asn = &geoPick{r: r, name: e.Name(), dir: dir, rank: dirRank + 1}
					continue
				}
			case strings.Contains(t, "city"):
				if place == nil || dirRank+2 > place.rank {
					if place != nil {
						_ = place.r.Close()
					}
					place = &geoPick{r: r, name: e.Name(), dir: dir, rank: dirRank + 2}
					continue
				}
			case strings.Contains(t, "country"):
				if place == nil || dirRank+1 > place.rank {
					if place != nil {
						_ = place.r.Close()
					}
					place = &geoPick{r: r, name: e.Name(), dir: dir, rank: dirRank + 1}
					continue
				}
			}
			_ = r.Close() // 同类库已经有了，多出来的关掉
		}
	}
	return place, asn, errMsg
}

// apply 把选中的库装进结构体（调用方负责加锁）。
func (g *GeoDB) apply(place, asn *geoPick) {
	if place != nil {
		g.place = place.r
		g.files = append(g.files, place.name)
		g.source = place.dir
		g.city = strings.Contains(strings.ToLower(place.r.Metadata.DatabaseType), "city")
		g.build = buildDate(place.r)
	}
	if asn != nil {
		g.asn = asn.r
		g.files = append(g.files, asn.name)
		if g.source == "" {
			g.source = asn.dir
		}
	}
	g.loaded = g.place != nil || g.asn != nil
	if g.loaded {
		g.err = ""
	}
}

// Reload 重新扫描目录并换上新库。
//
// 装完 City 库不需要重启进程：采集循环每秒都在查 geo，重启会让界面空几秒，
// 而且用户刚点了「安装」，最不该看到的就是「请重启应用」。
func (g *GeoDB) Reload() error {
	if g == nil {
		return fmt.Errorf("地理库未初始化")
	}
	place, asn, errMsg := geoScan(g.dirs)
	if place == nil && asn == nil {
		if errMsg == "" {
			errMsg = "没有找到可用的 mmdb"
		}
		return fmt.Errorf("%s", errMsg)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	if g.place != nil {
		_ = g.place.Close()
	}
	if g.asn != nil {
		_ = g.asn.Close()
	}
	g.place, g.asn = nil, nil
	g.files = nil
	g.source, g.city, g.build = "", false, ""
	g.apply(place, asn)
	// 旧缓存里的城市名可能来自旧库，留着会新旧混在一起
	g.cache = map[string]GeoInfo{}
	return nil
}

func buildDate(r *maxminddb.Reader) string {
	e := r.Metadata.BuildEpoch
	if e == 0 {
		return ""
	}
	return time.Unix(int64(e), 0).Format("2006-01-02")
}

func (g *GeoDB) Available() bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.loaded
}

// Lookup 查一个 IP。查不到返回零值，调用方不需要判断错误。
func (g *GeoDB) Lookup(ipStr string) GeoInfo {
	if g == nil || ipStr == "" {
		return GeoInfo{}
	}
	g.mu.RLock()
	if v, ok := g.cache[ipStr]; ok {
		g.mu.RUnlock()
		return v
	}
	loaded := g.loaded
	g.mu.RUnlock()
	if !loaded {
		return GeoInfo{}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return GeoInfo{}
	}

	var out GeoInfo
	g.mu.RLock()
	pReader, aReader := g.place, g.asn
	g.mu.RUnlock()

	if pReader != nil {
		var rec mmPlace
		if err := pReader.Lookup(ip, &rec); err == nil {
			cc, names := rec.Country.ISOCode, rec.Country.Names
			if cc == "" {
				cc, names = rec.RegisteredCountry.ISOCode, rec.RegisteredCountry.Names
			}
			out.CC = cc
			out.Name = pickName(names)
			out.City = pickName(rec.City.Names)
			// subdivisions 从大到小，第一个就是一级行政区（省/州）
			if len(rec.Subdivisions) > 0 {
				out.Region = pickName(rec.Subdivisions[0].Names)
			}
		}
	}
	if aReader != nil {
		var rec mmASN
		if err := aReader.Lookup(ip, &rec); err == nil {
			out.ASN = rec.Number
			out.Org = rec.Org
		}
	}

	g.mu.Lock()
	if len(g.cache) >= maxGeoCache {
		g.cache = map[string]GeoInfo{}
	}
	g.cache[ipStr] = out
	g.mu.Unlock()
	return out
}

// pickName 优先中文，其次英文，最后随便取一个非空的。
func pickName(names map[string]string) string {
	if len(names) == 0 {
		return ""
	}
	if s := names["zh-CN"]; s != "" {
		return s
	}
	if s := names["zh-TW"]; s != "" {
		return s
	}
	if s := names["en"]; s != "" {
		return s
	}
	for _, s := range names {
		if s != "" {
			return s
		}
	}
	return ""
}

func (g *GeoDB) Close() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.place != nil {
		_ = g.place.Close()
		g.place = nil
	}
	if g.asn != nil {
		_ = g.asn.Close()
		g.asn = nil
	}
	g.loaded = false
}

type GeoStatus struct {
	Available bool     `json:"available"`
	Files     []string `json:"files,omitempty"`
	Error     string   `json:"err,omitempty"`
	Dir       string   `json:"dir"`
	Source    string   `json:"source,omitempty"` // 内置 / 数据目录
	City      bool     `json:"city,omitempty"`
	Build     string   `json:"build,omitempty"`
}

// Status 给界面用。dir 是用户应该往里放库的那个目录。
func (g *GeoDB) Status() GeoStatus {
	st := GeoStatus{}
	if g == nil {
		return st
	}
	if len(g.dirs) > 0 {
		st.Dir = g.dirs[0]
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	st.Available = g.loaded
	st.Files = append([]string{}, g.files...)
	st.Error = g.err
	st.City = g.city
	st.Build = g.build
	switch {
	case g.source == "":
	case g.source == g.builtin:
		st.Source = "内置"
	default:
		st.Source = "数据目录"
	}
	return st
}
