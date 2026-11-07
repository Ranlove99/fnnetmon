package main

import (
	"fmt"
	"sync"
	"time"
)

// 界面上的「安装省市数据」。
//
// 48MB 的下载在 NAS 上要几分钟，同步 HTTP 请求一定超时，所以做成后台任务：
// POST /api/geo/fetch 立刻返回，进度挂在 /api/dns 的 geo_job 里给前端轮询。
//
// 装完直接 GeoDB.Reload()，不重启进程——用户刚点完「安装」就被要求重启应用，
// 是最让人怀疑「是不是没装上」的体验。热加载之后所有视图下一秒就有省市了。
type GeoJob struct {
	mu      sync.Mutex
	running bool
	phase   string // downloading / verifying / reloading / done / failed
	done    int64
	total   int64
	err     string
	at      int64
	geo     *GeoDB
	dir     string
}

// GeoJobState 是给前端的快照。字段都带 omitempty，
// 没在装的时候整个对象几乎是空的，不会把界面搞乱。
type GeoJobState struct {
	Running bool   `json:"running"`
	Phase   string `json:"phase,omitempty"`
	Done    int64  `json:"done,omitempty"`
	Total   int64  `json:"total,omitempty"`
	Err     string `json:"err,omitempty"`
	At      int64  `json:"at,omitempty"`
}

func NewGeoJob(geo *GeoDB, dir string) *GeoJob {
	return &GeoJob{geo: geo, dir: dir}
}

func (j *GeoJob) State() GeoJobState {
	if j == nil {
		return GeoJobState{}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return GeoJobState{
		Running: j.running,
		Phase:   j.phase,
		Done:    j.done,
		Total:   j.total,
		Err:     j.err,
		At:      j.at,
	}
}

// Start 起一个后台下载。已经在装就直接拒绝，别让用户连点五次开出五个连接。
func (j *GeoJob) Start() error {
	if j == nil {
		return fmt.Errorf("地理库未初始化")
	}
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return fmt.Errorf("正在安装中，稍等一下")
	}
	j.running, j.phase, j.done, j.total, j.err = true, "downloading", 0, 0, ""
	j.mu.Unlock()

	go func() {
		err := geoFetchTo(j.dir, func(done, total int64) {
			j.mu.Lock()
			j.done, j.total = done, total
			if total > 0 && done >= total {
				j.phase = "verifying"
			}
			j.mu.Unlock()
		})
		if err == nil {
			j.mu.Lock()
			j.phase = "reloading"
			j.mu.Unlock()
			if rerr := j.geo.Reload(); rerr != nil {
				err = fmt.Errorf("下载成功但加载失败：%v", rerr)
			}
		}

		j.mu.Lock()
		defer j.mu.Unlock()
		j.running = false
		j.at = time.Now().Unix()
		if err != nil {
			j.phase, j.err = "failed", firstLine(err.Error())
			return
		}
		j.phase, j.err = "done", ""
	}()
	return nil
}

// Remove 删掉 City 库并热加载回退到国家 + ASN。
// 磁盘紧张的用户装完发现 48MB 太占地方，得有个后悔药。
func (j *GeoJob) Remove() error {
	if j == nil {
		return fmt.Errorf("地理库未初始化")
	}
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return fmt.Errorf("正在安装中，等它结束再删")
	}
	j.mu.Unlock()

	if err := removeGeoCity(j.dir); err != nil {
		return err
	}
	if err := j.geo.Reload(); err != nil {
		return fmt.Errorf("已删除，但重新加载失败：%v", err)
	}
	j.mu.Lock()
	j.phase, j.err, j.at = "removed", "", time.Now().Unix()
	j.mu.Unlock()
	return nil
}
