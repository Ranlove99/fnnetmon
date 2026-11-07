## 改了什么

<!-- 一两句说清。一个 PR 只做一件事。 -->

## 为什么

<!-- 尤其是流量口径、nftables、安装钩子、桌面入口相关的改动，请写清根因和取舍。 -->

## 关联

Closes #

## 验证

- [ ] `cd src && gofmt -l .` 无输出
- [ ] `go vet ./...` 干净
- [ ] `go test ./... -count=1` 全过
- [ ] `./build.sh both` 出双平台 fpk 并通过拆包校验
- [ ] 改过内联 JS 的话，`node --check` 过了
- [ ] 真机装过（版本 / 架构：____），`server.log` 无新增报错
- [ ] 改过 `manifest` / `app/ui/config` / `cmd/` / `dashboard.html` → 已重新打包

## 真机环境

| 项 | 值 |
| --- | --- |
| fnOS 版本 | |
| 架构 | aarch64 / x86_64 |
| 起始版本 → 目标版本 | |
| 全新安装还是升级 | |

## 风险与回滚

<!-- 是否改了拦截规则、数据库结构、历史口径、安装钩子；出问题怎么退回。 -->

提交前请过一遍 [CONTRIBUTING.md](../CONTRIBUTING.md) 的检查表。
