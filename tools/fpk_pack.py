#!/usr/bin/env python3
"""
fnpack build 的纯 Python 兜底实现，用于没有 macOS 版 fnpack 的机器。

fpk 的封装规则（从 fnpack 1.2.3 的产物反解，已逐项比对）：
  · fpk 本身是 tar.gz。外层放 manifest / app.tgz / cmd / config /
    wizard / ICON.PNG / ICON_256.PNG。
  · app.tgz 也是 tar.gz，内容是 app/ 下的所有条目，再加一份外层 config/。
  · manifest 去掉空行、按最长 key 左对齐，末尾追加
    checksum = <app.tgz 的 MD5>。

这个实现只保证「结构、权限、manifest、校验值」与 fnpack 一致，
不保证 gzip 字节一致（mtime / 压缩级别不同，checksum 会跟着变但自洽）。
有 fnpack 时 build.sh 仍优先用 fnpack。

用法: fpk_pack.py <app 目录，如 pkg/fnnetmon> <输出 fpk>
"""
import gzip
import hashlib
import io
import sys
import tarfile
import time
from pathlib import Path

SKIP = {'.DS_Store', 'Thumbs.db', '__pycache__'}


def manifest_pairs(path):
    pairs = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, val = line.split('=', 1)
        key, val = key.strip(), val.strip()
        if key == 'checksum':          # 由本脚本重新生成
            continue
        pairs.append((key, val))
    if not pairs:
        raise SystemExit('manifest 是空的或格式不对: %s' % path)
    return pairs


def render_manifest(pairs, checksum):
    rows = pairs + [('checksum', checksum)]
    width = max(len(k) for k, _ in rows)
    return ''.join('%s = %s\n' % (k.ljust(width), v) for k, v in rows).encode('utf-8')


def _norm(ti):
    """Go archive/tar 写出来的属主是 uid/gid 0。"""
    ti.uid = 0
    ti.gid = 0
    ti.uname = ''
    ti.gname = ''
    return ti


def add_bytes(tar, name, data, mode=0o644):
    ti = tarfile.TarInfo(name)
    ti.size = len(data)
    ti.mode = mode
    ti.mtime = int(time.time())
    _norm(ti)
    tar.addfile(ti, io.BytesIO(data))


def add_file(tar, path, arcname):
    if path.name in SKIP:
        return
    ti = _norm(tar.gettarinfo(str(path), arcname=arcname))
    with path.open('rb') as fh:
        tar.addfile(ti, fh)


def add_dir(tar, path, arcname):
    """连目录条目本身一起写进去，和 fnpack 一致。"""
    if not path.exists():
        return
    tar.addfile(_norm(tar.gettarinfo(str(path), arcname=arcname)))
    for item in sorted(path.iterdir(), key=lambda p: p.name):
        if item.name in SKIP:
            continue
        sub = arcname + '/' + item.name
        if item.is_dir():
            add_dir(tar, item, sub)
        elif item.is_file():
            add_file(tar, item, sub)


def tar_bytes(fill):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        fill(tar)
    return buf.getvalue()


def gz_bytes(data):
    buf = io.BytesIO()
    # mtime=0 让同样的输入得到同样的字节，checksum 不会天天变。
    with gzip.GzipFile(fileobj=buf, mode='wb', filename='', mtime=0,
                       compresslevel=6) as gz:
        gz.write(data)
    return buf.getvalue()


def main():
    if len(sys.argv) != 3:
        raise SystemExit('用法: fpk_pack.py <app 目录> <输出 fpk>')
    root, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    if not (root / 'manifest').is_file() or not (root / 'app').is_dir():
        raise SystemExit('不是有效的 fpk 源目录: %s' % root)

    pairs = manifest_pairs(root / 'manifest')

    def fill_app(tar):
        for item in sorted((root / 'app').iterdir(), key=lambda p: p.name):
            if item.name in SKIP:
                continue
            if item.is_dir():
                add_dir(tar, item, item.name)
            elif item.is_file():
                add_file(tar, item, item.name)
        # fnpack 会把外层的 config/ 也塞进 app.tgz
        add_dir(tar, root / 'config', 'config')

    app_tgz = gz_bytes(tar_bytes(fill_app))
    checksum = hashlib.md5(app_tgz).hexdigest()
    manifest = render_manifest(pairs, checksum)

    def fill_fpk(tar):
        add_bytes(tar, 'app.tgz', app_tgz)
        add_dir(tar, root / 'cmd', 'cmd')
        add_dir(tar, root / 'config', 'config')
        for name in ('ICON.PNG', 'ICON_256.PNG'):
            add_file(tar, root / name, name)
        add_bytes(tar, 'manifest', manifest)
        add_dir(tar, root / 'wizard', 'wizard')

    out.write_bytes(gz_bytes(tar_bytes(fill_fpk)))
    print('Packing successfully. -> %s (%d bytes, checksum %s)'
          % (out, out.stat().st_size, checksum))


if __name__ == '__main__':
    main()
