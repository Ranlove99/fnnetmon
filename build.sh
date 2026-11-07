#!/bin/bash
# fnnetmon 构建脚本：交叉编译 + 图标 + 打包
#
#   ./build.sh            # 只出 ARM（默认，和以前一样）
#   ./build.sh arm64      # 只出 ARM
#   ./build.sh amd64      # 只出 x86_64
#   ./build.sh both       # 两个都出
#
# 产物按架构分开命名：pkg/fnnetmon_<版本>_<平台>.fpk
# （以前两个架构都写同一个 fnnetmon.fpk，出完 x86 就把 arm 覆盖了）
set -e
set -o pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# 缓存和 GOPATH 放在 tools/ 下，换机器后目录不存在也没关系，Go 会自己建。
export GOCACHE="${GOCACHE:-$ROOT/tools/gocache}"
export GOPATH="${GOPATH:-$ROOT/tools/gopath}"
export GOFLAGS=-mod=mod
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"

# 工具链优先用 tools/ 里固定的那份；源码包不带 Go SDK，新机器回落到系统 go。
GO="$ROOT/tools/go/bin/go"
if [ ! -x "$GO" ]; then
    GO="$(command -v go || true)"
fi
if [ -z "$GO" ]; then
    echo "找不到 Go 编译器：请装 Go 1.26 以上，或把 SDK 放到 tools/go/" >&2
    exit 1
fi

# 只用到 Python 标准库（gen_icon.py / fpk_pack.py），系统 python3 即可。
# 需要指定版本时用 PYTHON=/path/to/python3 ./build.sh。
PYBIN="${PYTHON:-}"
if [ -z "$PYBIN" ]; then
    PYBIN="$(command -v python3 || true)"
fi
if [ -z "$PYBIN" ]; then
    echo "找不到 python3（生成图标和打包要用）" >&2
    exit 1
fi

# fnpack 是 macOS x86_64 二进制，到 Linux/Windows 上跑不了。
# 没它、或者它跑失败，就用纯 Python 的等价实现（结构已和 fnpack 产物比对过）。
pack_fpk() {
    USE_PY=0
    [ "$(uname -s)" = "Darwin" ] || USE_PY=1
    [ -x "$ROOT/tools/fnpack" ] || USE_PY=1
    [ "${FNPACK:-}" = "python" ] && USE_PY=1
    if [ "$USE_PY" = "0" ] && ( cd "$ROOT/pkg" && "$ROOT/tools/fnpack" build --directory fnnetmon ) 2>&1 | tail -2; then
        return 0
    fi
    echo "    fnpack 不可用，改用 tools/fpk_pack.py（纯 Python，跨平台）"
    ( cd "$ROOT/pkg" && "$PYBIN" "$ROOT/tools/fpk_pack.py" fnnetmon fnnetmon.fpk )
}

case "${1:-arm64}" in
    arm64|arm|aarch64) TARGETS="arm64" ;;
    amd64|x86|x86_64)  TARGETS="amd64" ;;
    both|all)          TARGETS="arm64 amd64" ;;
    *) echo "用法: ./build.sh [arm64|amd64|both]" >&2; exit 2 ;;
esac

VERSION=$("$PYBIN" - "$ROOT/pkg/fnnetmon/manifest" <<'EOF'
import re,sys
s=open(sys.argv[1]).read()
m=re.search(r"^version\s*=\s*(\S+)", s, re.M)
print(m.group(1) if m else "0.0.0")
EOF
)
echo "==> 版本 ${VERSION} 目标: ${TARGETS}"

# 防回归：install_init 曾写死「只允许 aarch64」，把 x86 包挡在门外，
# 而且它自己打印的报错长得像应用中心提示，害得排查绕了一整轮。
if grep -q '仅支持 ARM64' "$ROOT/pkg/fnnetmon/cmd/install_init"; then
    echo "cmd/install_init 又写死了 ARM64 校验，x86 包会装不上" >&2
    exit 1
fi

echo "==> 生成图标"
"$PYBIN" "$ROOT/tools/gen_icon.py" >/dev/null

echo "==> 内置地理库"
# 只带 Country + ASN（约 12MB）。City 库原始 48MB，fpk 外层已 gzip，
# 塞进去就是 +25MB——换来的省市信息可以按需安装（fnnetmon geo fetch），
# 不该让每个用户都付这个体积。data/geo 里的 City 仍然保留给本地开发和测试用。
GEO_SRC="$ROOT/data/geo"
GEO_DST="$ROOT/pkg/fnnetmon/app/bin/geo"
rm -rf "$GEO_DST"
mkdir -p "$GEO_DST"
GEO_KEEP="GeoLite2-Country.mmdb GeoLite2-ASN.mmdb"
n=0
for f in $GEO_KEEP; do
    if [ -f "$GEO_SRC/$f" ]; then
        cp "$GEO_SRC/$f" "$GEO_DST"/
        n=$((n+1))
    fi
done
if [ -f "$GEO_SRC/NOTICE.txt" ]; then
    cp "$GEO_SRC/NOTICE.txt" "$GEO_DST"/
fi
if [ "$n" -gt 0 ]; then
    echo "    $n 个库（国家 + ASN），共 $(du -sh "$GEO_DST" | cut -f1)"
    if [ -f "$GEO_SRC/GeoLite2-City.mmdb" ]; then
        echo "    City 不打包；需要省市时用 fnnetmon geo fetch 装"
    fi
else
    echo "    没有 data/geo/*.mmdb，跳过（地理信息不可用，其余功能不受影响）"
fi

# manifest 是源文件，打包时临时改 platform，打完立刻还原，
# 免得构建把「仓库里应该是 arm」这个事实改掉。
MANIFEST="$ROOT/pkg/fnnetmon/manifest"
MANIFEST_BAK="$ROOT/.manifest.bak"
cp "$MANIFEST" "$MANIFEST_BAK"
trap 'cp "$MANIFEST_BAK" "$MANIFEST" 2>/dev/null; rm -f "$MANIFEST_BAK"' EXIT

OUTS=()
for ARCH in $TARGETS; do
    if [ "$ARCH" = "amd64" ]; then PLATFORM="x86"; else PLATFORM="arm"; fi

    echo
    echo "==> [$PLATFORM] 编译 linux/$ARCH"
    mkdir -p "$ROOT/dist"     # 源码包里不带 dist/，go build 不会自己建父目录
    ( cd "$ROOT/src" && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" \
        "$GO" build -trimpath -ldflags "-s -w" -o "$ROOT/dist/fnnetmon-linux-$ARCH" . )

    echo "==> [$PLATFORM] 组装"
    cp "$ROOT/dist/fnnetmon-linux-$ARCH" "$ROOT/pkg/fnnetmon/app/bin/fnnetmon"
    chmod +x "$ROOT/pkg/fnnetmon/app/bin/fnnetmon"
    cp "$MANIFEST_BAK" "$MANIFEST"
    # arch 和 platform 必须一起切：应用中心校验架构读的是 arch
    # （x86_64 / aarch64），只写 platform 会被当成 aarch64 而拒装 x86 包。
    "$PYBIN" - "$MANIFEST" "$PLATFORM" <<'EOF'
import re,sys
p,plat=sys.argv[1],sys.argv[2]
arch={'arm':'aarch64','x86':'x86_64'}[plat]
s=open(p).read()
s=re.sub(r"^arch\s*=.*$",     "arch                  = "+arch, s, count=1, flags=re.M)
s=re.sub(r"^platform\s*=.*$", "platform              = "+plat, s, count=1, flags=re.M)
open(p,"w").write(s)
EOF

    echo "==> [$PLATFORM] 打包"
    rm -f "$ROOT/pkg/fnnetmon.fpk"
    pack_fpk
    OUT="$ROOT/pkg/fnnetmon_${VERSION}_${PLATFORM}.fpk"
    mv "$ROOT/pkg/fnnetmon.fpk" "$OUT"
    OUTS+=("$OUT")
    echo "    产物: $OUT  ($(du -h "$OUT" | cut -f1))"
done

cp "$MANIFEST_BAK" "$MANIFEST"

echo
echo "==> 完成"
# stat -f%z 只在 macOS/BSD 有效，shasum 也不是所有 Linux 都装了。
# 这两个只是最后的打印，但 set -e 会让它们把整个构建判成失败，CI 上必须跨平台。
file_size() { wc -c < "$1" | tr -d '[:space:]'; }
sha16() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -c1-16
    else
        sha256sum "$1" | cut -c1-16
    fi
}
for f in "${OUTS[@]}"; do
    printf '    %-44s %10s B  %s\n' "$(basename "$f")" "$(file_size "$f")" "$(sha16 "$f")"
done
