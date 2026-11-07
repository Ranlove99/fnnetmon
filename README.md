# 流量哨兵 fnnetmon

![version](https://img.shields.io/badge/version-0.9.9-2ea44f)
![Go](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&logoColor=white)
![platform](https://img.shields.io/badge/fnOS-aarch64%20%7C%20x86__64-orange)
![license](https://img.shields.io/badge/license-MIT-blue)
![data](https://img.shields.io/badge/GeoLite2-CC%20BY--SA%204.0-lightgrey)

给 [飞牛 fnOS](https://www.fnosweb.com/) 写的网络流量监控：按**应用 / 服务 / 进程**排行，
把每个连接对应到域名、国家地区和运营方，还能按进程或域名拦出向访问。
单文件 Go 二进制 + 内嵌前端，没有 Node、没有运行时依赖，打包成 `.fpk` 后由应用中心安装。

> 面向 NAS 自用，需要 root 权限读内核连接表、抓 DNS 应答、操作 nftables。
> 只支持 Linux（fnOS / arm64 与 x86_64）；macOS / Windows 上可以编译和跑测试，但采集不到真实数据。

---

## 能做什么

| 能力 | 说明 |
| --- | --- |
| 应用/服务排行 | 按 `sock_diag` 拿到每个 socket 的 `tcpi_bytes_acked/received`，归并到 systemd 单元、应用中心包名、进程名 |
| 连接与容器 | 活跃连接、容器 veth 流量（进出方向翻转）、回环连接单独折叠 |
| 域名归因 | AF_PACKET 抓 DNS 应答建缓存，不依赖 TLS SNI，因此 QUIC / HTTP/3 也能覆盖 |
| 地理与 ASN | 内置 GeoLite2 Country + ASN，连接归属地与运营方直接显示；省市级按需下载 |
| 历史与导出 | SQLite 单表按分钟/小时/天 rollup，本地时区对齐；堆叠图 + 流式 CSV 导出 |
| 首次外联与拦截 | 记录程序第一次连过的 IP，可裁决并下发 nftables `meta cgroup` 规则 |
| 未归因下钻 | 只读 nft 统计表，把「网卡总量 − 已归因」拆成 UDP / 容器 netns / 内核转发 |
| 告警与自检 | 阈值 + 冷却推企业微信 / 钉钉 / Slack；自检页显示 RSS（扣掉 mmap）、goroutine、fd |
| Web 界面 | 响应式，≤760px 切底部 Tab，深色/浅色两套色板，列序统一「下行在前」 |

完整功能口径、口径定义和排障手册见 **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)**，
架构与取舍见 **[docs/方案设计.md](docs/方案设计.md)**。

---

## 快速开始

### 1. 装到 NAS

从 [Releases](../../releases) 下载对应架构的 `fnnetmon_<版本>_<平台>.fpk`
（`arm` = aarch64，`x86` = x86_64），在 fnOS 应用中心里手动安装，或用：

```bash
appcenter-cli install-fpk fnnetmon_0.9.9_x86.fpk   # 按实际架构换文件名
```

装好后点桌面「流量哨兵」图标，或浏览器直接开 `http://<NAS IP>:18089/`。
另有一个「流量哨兵（直连备用）」图标，用于网关反代异常时保底。

> 0.9.5 / 0.9.6 的 x86 包因安装钩子写死 ARM64 而装不上，请使用 0.9.7 及以上版本。

### 2. 从源码构建

前置：Go 1.26+、Python 3（只用标准库）。不需要 Node、CGO 或 Docker。

```bash
git clone https://github.com/Ranlove99/fnnetmon.git
cd fnnetmon
./build.sh both          # 或 ./build.sh arm64 / ./build.sh amd64
```

产物在 `pkg/fnnetmon_<版本>_<平台>.fpk`。构建脚本会：

1. 交叉编译 `CGO_ENABLED=0 GOOS=linux` 的纯 Go 二进制到 `dist/`；
2. 用 `tools/gen_icon.py` 生成图标；
3. 把 Country / ASN 两个 mmdb 放进 `app/bin/geo/`（City 不进包）；
4. 临时切换 `manifest` 的 `arch` 与 `platform`，用 `tools/fpk_pack.py` 打成 fpk，然后还原 manifest。

macOS 上如果有 `tools/fnpack` 会优先用官方打包器；Linux / 没有 fnpack 时自动回落到纯 Python 实现，
两者产物结构一致。可用 `FNPACK=python ./build.sh both` 强制走 Python。

### 3. 本地开发与测试

```bash
cd src
go vet ./...
go test ./... -count=1
go run . serve --addr 127.0.0.1:18089 --var /tmp/fnnetmon
```

CLI 子命令：`serve | snapshot | diag | svc | geo | firewall | selfcheck | version`。
完整参数见 `src/main.go`；非 Linux 上没有真实连接数据，`serve` 只能用来验接口形状。

```bash
fnnetmon geo status       # 看当前加载了哪些地理库
fnnetmon geo fetch        # 在 NAS 上下载 48MB 的 City 库到数据目录
fnnetmon selfcheck        # 资源占用自检
fnnetmon svc              # 核对应用中心服务名归因
```

---

## 地理数据

| 文件 | 是否入库 | 用途 |
| --- | --- | --- |
| `data/geo/GeoLite2-Country.mmdb` | ✅ 入库（约 3.2MB） | 随 fpk 分发，国家与地区 |
| `data/geo/GeoLite2-ASN.mmdb` | ✅ 入库（约 8.6MB） | 随 fpk 分发，运营方 / AS 号 |
| `data/geo/GeoLite2-City.mmdb` | ❌ 不入库（48MB） | 仅本地省市单测与手动安装需要 |

仓库里不含 City 库时，跑完整测试用：

```bash
./scripts/fetch_geo.sh          # 下载到 data/geo/，已被 .gitignore 忽略
cd src && go test ./... -count=1
```

不下载也不会导致 CI 失败：`src/m13_test.go` 检测到缺库会 `t.Skip`。
数据来源与署名见 [data/geo/README.md](data/geo/README.md) 和 `data/geo/NOTICE.txt`。

---

## 目录结构

```
fnnetmon/
├── .github/
│   ├── workflows/ci.yml               # go vet / go test / 双平台构建 + 产物上传
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   └── pull_request_template.md
├── .gitignore
├── .gitattributes                     # 强制 shell / 脚本 LF，mmdb 与 PNG 按二进制处理
├── LICENSE                            # MIT
├── README.md                          # 本文件
├── CHANGELOG.md
├── CONTRIBUTING.md
├── build.sh                           # 交叉编译 + 图标 + fpk 打包
├── data/geo/                          # Country + ASN（入库）、NOTICE、下载说明
├── docs/
│   ├── USER_GUIDE.md                  # 完整用户手册 / 口径定义 / 排障（原 README）
│   └── 方案设计.md                    # 架构设计与技术取舍
├── scripts/fetch_geo.sh               # 按需下载 City 库
├── src/                               # Go 源码 + go:embed 的前端
│   ├── go.mod / go.sum
│   ├── main.go / server.go / state.go
│   ├── diag.go / conn.go / proc.go / svc.go / dns.go / geo.go / ...
│   ├── firewall.go / peer.go / stats.go / alerts.go / store.go / ...
│   ├── assets/dashboard.html           # 单页前端，编译进二进制
│   └── *_test.go                       # 单元测试
├── pkg/fnnetmon/                      # fnOS 应用打包模板
│   ├── manifest                        # 版本、架构、变更日志
│   ├── cmd/                            # install / upgrade / uninstall / main 生命周期钩子
│   ├── config/                         # 权限与资源声明
│   ├── app/ui/config                   # 桌面入口（18089 端口反代 + 直连备用）
│   ├── app/ui/images/                  # 图标
│   └── ICON.PNG / ICON_256.PNG
└── tools/                             # 纯 Python 打包与图标工具
    ├── fpk_pack.py
    ├── gen_icon.py
    └── make_src_bundle.py
```

---

## 设计上容易踩的坑

维护者请在动代码前读一遍 [CONTRIBUTING.md](CONTRIBUTING.md)，这里只列最反直觉的几条：

- **回环连接有两个 socket**，两端字节互为镜像，两端都记会出现各占 50% 的两行；只按本地端口大的一端记账。
- **容器 socket 在独立 netns**，宿主机 `sock_diag` 看不到，容器流量只能从 veth 取，且 `tx`/`rx` 要翻转。
- **UDP 没有字节计数**，只显示连接数，不伪造数据。
- **历史库按本地时区对齐时间桶**，并按目标粒度对齐 rollup 起点，否则「按天」会切在 UTC 00:00。
- **nft 的 `fwd` 是关键字**，`chain fwd` 会直接语法错误；统计链统一用 `fnm_out` / `fnm_fwd`。
- **观测和拦截是两个模块**，前者只读、后者改 nft 规则，不要合并。
- **fnOS 网关经 Unix socket 转发时可能不带 Host**，Go `net/http` 会在解析阶段直接 400；
  `hostFixListener` 只在 socket 首次 Read 补合法 Host，TCP 直连不受影响。

---

## 上传到 GitHub

本目录已经是可直接提交的仓库根（不含 `.git`、缓存、成品包与本机 SDK）：

```bash
cd fnnetmon
git init -b main
git add .
git commit -m "Initial import: fnnetmon 0.9.9"
git remote add origin https://github.com/Ranlove99/fnnetmon.git
git push -u origin main
```

push 后 `.github/workflows/ci.yml` 会自动跑 `go vet`、单测和双平台构建，
并上传两个 `.fpk` 作为 workflow artifact。若要用 GitHub Releases 分发 fpk，
给 tag 打 `v*` 后 CI 会附带产物（见 workflow 里的 release job）。

> CI 在 Linux 上走纯 Python 打包器，与 macOS 官方 `fnpack` 的产物结构一致、
> 压缩流不同，因此 artifact 的大小和哈希与本地正式包不会相同，属正常。
> 正式发布包建议在 macOS 上用 `./build.sh both` 出，并做一次真机安装验证。

> `pkg/fnnetmon/cmd/*` 是没有扩展名的 shell 脚本，`.gitattributes` 强制它们用 LF。
> Windows 上请设置 `git config core.autocrlf false`，否则安装钩子会带 CRLF 而执行失败。

---

## 已知限制

- 只支持 Linux；采集依赖 `AF_PACKET`、`sock_diag`、nftables，需 root / `CAP_NET_ADMIN`。
- 未归因流量 = 网卡总量 − 已归因，包含 UDP 无字节、容器 netns、无主 socket、内核态转发，属正常差额。
- 域名归因依赖能抓到 DNS 应答；DoH / 加密 DNS 不经过明文 DNS 应答时无法覆盖。
- 官方应用中心 `appcenter-cli list` 的真实输出格式、真机 nft 统计表细分仍需在设备上复核。

---

## 许可与致谢

- 源代码：**MIT**，见 [LICENSE](LICENSE)。
- 地理数据：GeoLite2 由 MaxMind 创建，按 **CC BY-SA 4.0** 发布，署名与改动声明见 `data/geo/NOTICE.txt`。
  CC BY-SA 只覆盖数据库及其衍生数据，不约束本项目源代码。
- 依赖：[modernc.org/sqlite](https://modernc.org/sqlite)（纯 Go SQLite）、
  [maxminddb-golang](https://github.com/oschwald/maxminddb-golang)。
- City 库镜像：[P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb)。
