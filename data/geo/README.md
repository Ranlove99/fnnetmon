# 地理数据

本目录放构建 fpk 时内置的 MaxMind GeoLite2 数据库。

| 文件 | 大小 | 是否入库 | 作用 |
| --- | --- | --- | --- |
| `GeoLite2-Country.mmdb` | 约 3.2MB | ✅ | 国家 / 地区，随 fpk 分发 |
| `GeoLite2-ASN.mmdb` | 约 8.6MB | ✅ | 运营方 / AS 号，随 fpk 分发 |
| `GeoLite2-City.mmdb` | 约 48MB | ❌ | 省 / 市，仅本地单测与手动安装需要 |

## 为什么 City 不入库

fpk 外层本身是 gzip，把 48MB 的 City 塞进去几乎没有压缩收益，却让每个用户多下载约 25MB。
省市级数据改为按需获取：

- 本地开发 / 跑完整单测：`./scripts/fetch_geo.sh`（下载到本目录，已被 `.gitignore` 忽略）。
- 已装好的 NAS：界面「概览 → 域名归因 → 地理 / ASN」点安装，或执行 `fnnetmon geo fetch`。
- 手动放置：把 mmdb 放进数据目录（默认 `/vol1/@appdata/fnnetmon/geo/`），
  数据目录优先级高于内置库，不需要重新打包或升级应用。

`src/m13_test.go` 检测到本目录没有 City 库时会 `t.Skip`，因此 CI 默认不会因缺库失败。
手动触发 `workflow_dispatch` 时 CI 会先跑下载脚本，再执行完整地理单测。

## 构建时怎么处理

`build.sh` 只把 Country / ASN 两个文件和 `NOTICE.txt` 复制进
`pkg/fnnetmon/app/bin/geo/`，City 一律不打包。该目录由构建脚本重建，
不要手工往里面放库文件。

## 许可与署名

GeoLite2 数据由 MaxMind 创建，来源 <https://www.maxmind.com>，
按 **CC BY-SA 4.0** 发布。完整署名与「相同方式共享」说明见 [NOTICE.txt](NOTICE.txt)。

要点：文件原样分发、未做修改；数据库及其衍生数据继续适用 CC BY-SA 4.0；
本项目的源代码不受该许可约束（源代码是 MIT，见根目录 `LICENSE`）。

数据日期见各文件内嵌的 build epoch，界面自检页会显示实际加载的是内置库还是数据目录里的库。
