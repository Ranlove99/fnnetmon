# 更新日志

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。
0.9.9 之前的条目整理自 fpk `manifest` 里的 `changelog` 字段（此前没有独立仓库）。

## [0.9.9] - 2026-11-07

### 修复

- **桌面图标 400 Bad Request**（0.9.7 起就有，与 CPU 架构无关）：fnOS 网关经 `app.sock`
  转发时可能不带 `Host` 或把 socket 路径当 `Host`，Go `net/http` 在请求解析阶段直接返回 400，
  handler 根本没执行。新增 `hostFixListener`：只在 Unix socket 首次 `Read` 补合法 `Host`，
  不碰请求行、路径和 body；配合 `SetKeepAlivesEnabled(false)` 保证一连接一请求。
- 桌面主入口改为按 `18089` 端口反代（`iframe` + `protocol: http`），移除
  `gatewayPrefix` / `gatewaySocket`；放出「流量哨兵（直连备用）」图标保底。
- 前端 `apiBase()` 与后端 `stripGatewayPrefix` 同时兼容 `/api/` 与 `/app/fnnetmon/api/`。

## [0.9.8] - 2026-11-07

### 修复

- nft 统计表 `chain fwd` 建不起来：`fwd` 是 nft 关键字（`fwd to <dev>`），日志报
  `syntax error, unexpected fwd, expecting string`，导致「未归因」下钻静默关闭。
  链名改为 `fnm_out` / `fnm_fwd`，按 `counter.comment` 归类（旧表仍可读）。
- 统计表建表增加「出向 + 转发 → 仅出向」降级、半张表自动重建、失败后台重试。
- 停止服务时 `firewall off` 不再打印不存在的表的原始 nft 报错和误导性「请停止服务」提示。

## [0.9.7] - 2026-11-06

### 修复

- **x86 装不上的真正原因**：`cmd/install_init` 写死只放行 `aarch64`，且它自己打印的
  「本安装包仅支持 ARM64 设备」长得像系统提示，导致 0.9.6 把问题误判成 `arch` 字段。
  改为读包内二进制 ELF `e_machine`（偏移 18）自适应，两平台共用一份脚本。
- 0.9.5 / 0.9.6 的 x86 包均不可用，请勿分发。

### 构建

- 源码转移包与双平台 fpk 生成脚本补齐；`build.sh` 增加 `install_init` 防回归断言。

## [0.9.6] - 2026-11-06

### 修复

- `manifest` 补 `arch` 字段（`aarch64` / `x86_64`），与 `platform` 一起随构建切换。
  应用中心校验架构读的是 `arch`，缺它时按默认 aarch64 处理。此版 x86 仍装不上，见 0.9.7。

## [0.9.5] - 2026-11-05

### 界面

- 概览页「活跃连接 / 容器」两张半空卡合并为一张双指标卡；外联页长路径只留末两段并加悬停提示。
- 历史页色板按排名分档（前三高饱和、4–6 换色相、7+ 转灰），图例显示占比。
- 字号从七档小数收成 10/11/12/13/14 五档；320px 下数字与名字不再互相挤压；
  排行榜卡片锁单行 + 省略号；≤760px 切底部 Tab。

## [0.9.4] - 2026-11-05

### 修复

- 应用中心安装的应用显示真名而不是 `trim.xxx`：按 `/proc/<pid>/exe` 路径里的
  `@appcenter` / `@appstore` 段取包名，再按 `appcenter-cli list` > manifest `display_name` >
  入口 `title` > 内置表（178 条）> 包名的优先级取名，并剥掉 manifest 值里的引号。

## [0.9.3] - 2026-11-03

### 新增

- `fnnetmon svc` 服务名核对命令；代码结构重整（`server.go` 拆出 handler 依赖、`api_*.go` 分文件）。

## [0.9.2] - 2026-11-02

### 新增

- 历史页支持按应用维度查看（库里只存进程维度，查询时经 `svcOf` 归并）。

## [0.9.1] - 2026-11-01

### 修复

- 列表点击不跳动（`CSIG` 结构指纹 + `patchConns()` 原地更新，排序时才重建）。
- KPI 合并曲线、显示省市级地理信息。

## [0.9.0] - 2026-10-31

### 新增

- 界面重做；基础包体积降到约 11.7MB；未归因下钻（只读 nft 统计表）；
  流量阈值告警（企业微信 / 钉钉 / Slack）；历史数据 CSV 流式导出。

## [0.8.1] / [0.8.0] / [0.7.0] / [0.6.0] / [0.5.0]

- 0.8.1：应用名贯穿所有视图。
- 0.8.0：内置 GeoLite2 国家与 ASN 数据库。
- 0.7.0：修正流量口径（回环不计入网络流量、未归因作为排行正式一行）。
- 0.6.0：排行视图。
- 0.5.0：域名归因（AF_PACKET 抓 DNS 应答）。
