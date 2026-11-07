#!/usr/bin/env python3
"""
把「能继续开发」的源码打成一个 tar.gz，方便搬到另一台机器。

排除的都是可重建或跟机器绑定的东西：
  tools/go / gopath / gocache（1.5 GB 缓存与 SDK）、dist/、pkg/*.fpk、
  pkg/fnnetmon/app/bin/（构建时重建）、src/fnnetmon（旧的本机二进制）、
  .DS_Store / __pycache__ / *.pyc。

保留：src/、构建脚本、Go 模块清单、打包模板、GeoLite2 三个库
（City 是本地跑省市相关单测要用的）、设计文档、开发笔记。

用法: python3 tools/make_src_bundle.py [输出路径]
"""
import gzip
import io
import os
import re
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent          # fnnetmon/
WORKSPACE = ROOT.parent
BUNDLE_NAME = 'fnnetmon'

SKIP_NAMES = {'.DS_Store', 'Thumbs.db', '__pycache__', '.git', '.manifest.bak'}
SKIP_SUFFIX = {'.pyc', '.out', '.log', '.db', '.sqlite', '.sqlite3', '.fpk', '.test'}
TOOLS_KEEP = {'gen_icon.py', 'fnpack', 'fpk_pack.py', 'make_src_bundle.py'}
TOP_KEEP = {'README.md', 'build.sh', 'src', 'tools', 'data', 'pkg', 'docs'}


def version():
    text = (ROOT / 'pkg/fnnetmon/manifest').read_text(encoding='utf-8')
    m = re.search(r'^version\s*=\s*(\S+)', text, re.M)
    return m.group(1) if m else 'dev'


def keep(rel):
    """rel 是相对 fnnetmon/ 的 Path。"""
    parts = rel.parts
    if not parts or parts[0] not in TOP_KEEP:
        return False
    if any(p in SKIP_NAMES for p in parts):
        return False
    if rel.suffix in SKIP_SUFFIX:
        return False
    top = parts[0]
    if top == 'tools' and len(parts) > 1 and parts[1] not in TOOLS_KEEP:
        return False                                   # go / gopath / gocache
    if top == 'src' and len(parts) == 2 and parts[1] == 'fnnetmon':
        return False                                   # 旧 Mach-O 二进制
    if top == 'pkg':
        if 'app' in parts and 'bin' in parts:
            return False                               # 构建时重建
    return True


def collect():
    files = []
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in SKIP_NAMES]
        for name in names:
            path = Path(base) / name
            rel = path.relative_to(ROOT)
            if keep(rel):
                files.append((rel, path))
    return sorted(files, key=lambda x: str(x[0]))


def add(tar, arcname, data, mode):
    ti = tarfile.TarInfo(arcname)
    ti.size = len(data)
    ti.mode = mode
    ti.mtime = 0
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ''
    tar.addfile(ti, io.BytesIO(data))


def main():
    ver = version()
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else \
        WORKSPACE / ('%s-src_%s.tar.gz' % (BUNDLE_NAME, ver))

    files = collect()
    # 开发笔记在工作区的 .workbuddy-ai/memory/ 里，不在项目目录内，单独收进来。
    notes_dir = WORKSPACE / '.workbuddy-ai/memory'
    notes = sorted(notes_dir.glob('*.md')) if notes_dir.is_dir() else []

    raw = io.BytesIO()
    total = 0
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
        # 空目录 wizard/ 要显式写，否则解压后 fnpack 少了这个目录条目
        d = tarfile.TarInfo('%s/pkg/fnnetmon/wizard' % BUNDLE_NAME)
        d.type, d.mode, d.mtime = tarfile.DIRTYPE, 0o755, 0
        d.uid = d.gid = 0
        d.uname = d.gname = ''
        tar.addfile(d)

        for rel, path in files:
            data = path.read_bytes()
            mode = 0o755 if (path.stat().st_mode & 0o111) else 0o644
            add(tar, '%s/%s' % (BUNDLE_NAME, rel.as_posix()), data, mode)
            total += len(data)
        for note in notes:
            add(tar, '%s/docs/dev-notes/%s' % (BUNDLE_NAME, note.name),
                note.read_bytes(), 0o644)
            total += note.stat().st_size

    packed = io.BytesIO()
    with gzip.GzipFile(fileobj=packed, mode='wb', filename='', mtime=0,
                       compresslevel=6) as gz:
        gz.write(raw.getvalue())
    out.write_bytes(packed.getvalue())

    print('源码包: %s' % out)
    print('  %d 个项目文件 + %d 份开发笔记，原始 %.1f MB → 压缩后 %.1f MB'
          % (len(files), len(notes), total / 1048576, out.stat().st_size / 1048576))
    must = ['build.sh', 'README.md', 'src/go.mod', 'src/go.sum',
            'src/assets/dashboard.html',
            'tools/fpk_pack.py', 'tools/gen_icon.py',
            'data/geo/GeoLite2-Country.mmdb', 'data/geo/GeoLite2-ASN.mmdb',
            'data/geo/GeoLite2-City.mmdb', 'pkg/fnnetmon/manifest']
    names = {f[0].as_posix() for f in files}
    missing = [m for m in must if m not in names]
    print('  必备文件: %s' % ('齐全' if not missing else '缺 ' + ', '.join(missing)))
    if missing:
        sys.exit(1)


if __name__ == '__main__':
    main()
