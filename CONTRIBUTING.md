# 参与开发

欢迎提 Issue 和 PR。这个项目面向 fnOS NAS，很多行为只能在真机上验证，
所以**说明你的设备环境**比贴一大段代码更有用。

## 环境

| 项 | 要求 |
| --- | --- |
| Go | 1.26+（见 `src/go.mod`），纯 Go，不需要 CGO |
| Python | 3.x，只用标准库（生成图标、打 fpk） |
| 打包 | `tools/fpk_pack.py` 跨平台；macOS 可选 `tools/fnpack` |
| 真机 | fnOS 1.2+ / aarch64 或 x86_64 / root 或 `CAP_NET_ADMIN` |

macOS / Windows 上可以 `go vet`、`go test` 和 `serve` 看接口形状，
但 `procs` 恒空——采集依赖 Linux 的 `sock_diag` 与 `AF_PACKET`，
**不要在非 Linux 上判断「功能坏了」**。

```bash
./build.sh both                     # 双平台 fpk
cd src && go vet ./... && go test ./... -count=1
./scripts/fetch_geo.sh              # 可选：拉 48MB City 库，跑完整地理单测
fnnetmon selfcheck                  # 真机：RSS / goroutine / fd
```

CI（`.github/workflows/ci.yml`）跑的就是上面这几步，PR 前本地跑一遍能省一轮。

## 提交前检查表

- [ ] `cd src && gofmt -l .` 无输出，`go vet ./...` 干净，`go test ./... -count=1` 全过。
- [ ] 改了 `src/assets/dashboard.html` 里的内联脚本后，把脚本抽出来 `node --check` 过一遍
      （少一个反引号会让整页 JS 静默不执行）。
- [ ] 新增对外 JSON 结构体**必须写 `json tag`**；漏一个前端就是整页 `undefined`。
- [ ] 改了 `manifest` / `app/ui/config` / `cmd/` 安装钩子 / `dashboard.html`，
      必须重新 `./build.sh` 打包——入口配置在 `app.tgz` 内，不重打等于没改。
      只改 README / docs 不需要重打。
- [ ] 装到真机后看 `server.log`：不应出现 `unattr breakdown off`；桌面图标不应 400。

## 代码约定（踩过坑的）

- **列序统一「下行在前」**：顶栏、KPI 卡、排行卡、连接表、容器表。
- 前端字号只有 10 / 11 / 12 / 13 / 14 五档，不要小数号；不用 `color-mix()`（要 Chrome 111+）；
  不要用 Unicode 几何符号当图标（WebView 缺字形，用 CSS border）。
- 窄屏的长名字 / 路径一律 `nowrap` + 省略号，完整值放 `title`；右侧数字容器要 `flex:none`。
- 采集路径里的 netlink 必须设 `SO_RCVTIMEO`，否则 `Recvfrom` 无超时会永久卡住，
  表现为「进程活着、端口通、页面不更新」。
- `PeerTracker.Observe` 里**绝不能做 IO**（SQLite `busy_timeout` 会卡住 1 秒一次的 tick）。
- 时间桶按本地时区对齐 `((ts+off)/w)*w-off`；rollup 重算窗口起点必须对齐目标粒度；
  查询序列长度必须等于时间轴（缺桶补 0），否则堆叠图错位。
- 归并后同桶多行**必须累加**再写回 map，直接赋值只在「一 key 一桶一行」时碰巧对。
- CSV 用 `ExportRows(io.Writer)` 流式写，`beginCSV()` 统一写 UTF-8 BOM（Excel 中文乱码）。
- 域名规则解析不到地址要跳过并标红，**绝不裸拦全部出向**；`th dport` 前必须有 l4 匹配。
- nft 链名一律加 `fnm_` 前缀，别用 `fwd` / `out` 这类单词（nft lexer 关键字）。
- 拦截安全阀一条都不能删：`policy accept`、私网/回环/组播白名单、`nft -c` 预检、
  整表原子替换、cgroup 不存在则跳过并标红、SIGTERM 清表、紧急停止。
- 企业微信和钉钉 Webhook **出错也返回 HTTP 200**，错误在 body 的 `errcode`，必须解析。
- 不要用 `sed -i ''`（BSD/macOS 与 GNU 语法不同），改文件用 Python 或编辑器。
- 改 `cmd/*` 后确认文件仍是 LF 且可执行；`.gitattributes` 已经帮你处理换行。

## 提交与 PR

- 提交信息用简短中文或英文祈使句，例如 `fix: nft 统计链名避开 fwd 关键字`。
- 一个 PR 只做一件事；涉及口径、拦截、安装钩子的改动请写清**为什么**，最好附真机日志片段。
- 请在 PR 描述里给出：fnOS 版本、CPU 架构、fpk 版本、验证方式、是否测过升级安装。

## 报告问题

用 `.github/ISSUE_TEMPLATE/bug_report.md` 模板，务必附上：

1. `server.log` 里相关几行（路径 `<var>/server.log`，注意抹掉内网敏感信息）；
2. `/api/debug` 的输出或自检页截图；
3. 是全新安装还是升级安装、上一个版本号是多少。

`400 Bad Request`、装不上、页面不更新这三类问题的定位顺序见
[docs/USER_GUIDE.md](docs/USER_GUIDE.md) 的「排查」章节。
