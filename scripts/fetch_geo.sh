#!/usr/bin/env bash
# 按需下载 GeoLite2-City.mmdb（约 48MB）。
#
# 仓库与 fpk 都只带 Country + ASN，City 太大，只在下面两种场景需要：
#   1. 跑完整地理单测（src/m13_test.go 会读 data/geo/GeoLite2-City.mmdb）
#   2. 想让界面显示省 / 市（也可以用 fnnetmon geo fetch 装到 NAS 数据目录）
#
# 用法：
#   ./scripts/fetch_geo.sh
#   GEO_CITY_URL=https://.../GeoLite2-City.mmdb ./scripts/fetch_geo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$ROOT/data/geo"
TARGET="$DEST/GeoLite2-City.mmdb"

# 与 src/geocmd.go 的 geoCityURL 保持一致。官方站要 license key，
# 这里走公开镜像；失效时请用 GEO_CITY_URL 覆盖，或手动把文件放进 data/geo/。
URL="${GEO_CITY_URL:-https://ghproxy.net/https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-City.mmdb}"

if [ -f "$TARGET" ]; then
    echo "已存在：$TARGET ($(wc -c < "$TARGET" | tr -d ' ') B)，跳过下载"
    exit 0
fi

mkdir -p "$DEST"
TMP="$(mktemp "$DEST/.GeoLite2-City.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

echo "下载 City 库：$URL"
if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 20 --max-time 600 -o "$TMP" "$URL"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TMP" "$URL"
else
    echo "需要 curl 或 wget" >&2
    exit 1
fi

size="$(wc -c < "$TMP" | tr -d ' ')"
if [ "$size" -lt 10000000 ]; then
    echo "下载内容只有 $size B，不像完整的 City 库（应约 48MB），已丢弃" >&2
    exit 1
fi

mv "$TMP" "$TARGET"
trap - EXIT
echo "完成：$TARGET ($size B)"
echo "该文件已被 .gitignore 忽略，不会提交。运行 cd src && go test ./... 可跑完整地理单测。"
