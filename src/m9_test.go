package main

import (
	"math"
	"testing"
)

// 地理库是 mmap 的，页会慢慢变驻留并算进 VmRSS。自检要把这部分扣掉，
// 否则「装了个 48MB 的 City 库」和「内存泄漏」在数字上没法区分。
// 解析一旦失效，geo_mb 会静默变成 0，预算照样被顶穿——所以这条必须锁住。
func TestParseGeoRSS(t *testing.T) {
	// 注意用真实换行：smaps 是逐行格式，反引号里的 \n 是两个字面字符。
	const smaps = `55d0a3b1e000-55d0a3b2a000 r--p 00000000 08:01 1234  /usr/bin/fnnetmon
Size:                48 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:                 40 kB
Pss:                 40 kB

7f2c00000000-7f2c03000000 r--p 00000000 08:01 5678  /vol1/@appdata/fnnetmon/GeoLite2-City.mmdb
Size:             49152 kB
KernelPageSize:        4 kB
MMUPageSize:           4 kB
Rss:               8192 kB
Pss:               8192 kB

7f2c04000000-7f2c06000000 r--p 00000000 08:01 5679  /vol1/@appdata/fnnetmon/GeoLite2-ASN.mmdb
Size:             20480 kB
Rss:               2048 kB

7f2c06000000-7f2c07000000 r--p 00000000 08:01 5680  /usr/lib/libc.so.6
Size:              1024 kB
Rss:                900 kB
`
	// 8192 + 2048 = 10240 KB = 10 MB；libc 和二进制自己都不该算进来
	if got := parseGeoRSS(smaps); math.Abs(got-10.0) > 0.001 {
		t.Fatalf("应只累加 mmdb 映射，got %.3f MB want 10.000", got)
	}

	if got := parseGeoRSS(""); got != 0 {
		t.Fatalf("空输入应为 0，got %v", got)
	}

	// 没有 mmdb 时必须是 0，不能把别的映射算进去
	const noGeo = `7f00-7f01 r--p 0 08:01 1 /usr/bin/fnnetmon
Rss: 100 kB
`
	if got := parseGeoRSS(noGeo); got != 0 {
		t.Fatalf("没有 mmdb 时应为 0，got %v", got)
	}

	// 一个映射头后面跟着多个 Rss 行只算一次（真实的 smaps 里就一行）
	const oneLine = `7f00-7f01 r--p 0 08:01 1 /x/GeoLite2-Country.mmdb
Rss: 1024 kB
`
	if got := parseGeoRSS(oneLine); math.Abs(got-1.0) > 0.001 {
		t.Fatalf("1024 KB 应为 1 MB，got %v", got)
	}
}
