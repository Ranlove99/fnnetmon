#!/usr/bin/env python3
"""生成 fnnetmon 应用图标（纯标准库，无 Pillow 依赖）。"""
import zlib, struct, math, os

SS = 4  # 超采样倍数


def rounded_rect(x, y, rx, ry, rw, rh, r):
    if x < rx or x > rx + rw or y < ry or y > ry + rh:
        return False
    cx = min(max(x, rx + r), rx + rw - r)
    cy = min(max(y, ry + r), ry + rh - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def blend(dst, src, a):
    return tuple(int(dst[i] * (1 - a) + src[i] * a) for i in range(3))


def sample(x, y, size):
    """返回该点的 RGBA"""
    bg = (24, 95, 165)      # #185FA5
    bars = (255, 255, 255)
    accent = (159, 225, 203)  # #9FE1CB
    col = (0, 0, 0)
    alpha = 0

    if rounded_rect(x, y, 8, 8, size - 16, size - 16, size * 0.22):
        col, alpha = bg, 1.0
        unit = size / 256.0
        bars_def = [(40, 60), (88, 96), (136, 132), (184, 168)]
        base = 196 * unit
        bw = 32 * unit
        for i, (bx, bh) in enumerate(bars_def):
            x0 = bx * unit
            y0 = base - bh * unit
            if rounded_rect(x, y, x0, y0, bw, bh * unit, 8 * unit):
                col = accent if i == 3 else bars
                break
    return col, alpha


def render(size):
    buf = bytearray()
    for py in range(size):
        buf.append(0)  # filter type 0
        for px in range(size):
            r = g = b = a = 0.0
            for sy in range(SS):
                for sx in range(SS):
                    x = px + (sx + 0.5) / SS
                    y = py + (sy + 0.5) / SS
                    c, al = sample(x, y, size)
                    if al > 0:
                        r += c[0]; g += c[1]; b += c[2]; a += 1
            n = SS * SS
            if a > 0:
                buf += bytes((int(r / a), int(g / a), int(b / a), int(a / n * 255)))
            else:
                buf += bytes((0, 0, 0, 0))
    return bytes(buf)


def write_png(path, size):
    raw = render(size)
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)
    print(f"{path}  {size}x{size}  {len(png)} bytes")


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "..", "pkg", "fnnetmon")
    write_png(os.path.join(out, "ICON.PNG"), 256)
    write_png(os.path.join(out, "ICON_256.PNG"), 256)
    os.makedirs(os.path.join(out, "app/ui/images"), exist_ok=True)
    write_png(os.path.join(out, "app/ui/images/icon_256.png"), 256)
    write_png(os.path.join(out, "app/ui/images/icon_64.png"), 64)
