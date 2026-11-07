package main

import (
	"bytes"
	"net"
	"net/http"
	"strings"
)

// server 把 runServe 里的依赖收成一个结构体。
//
// 原来这些依赖全是 runServe 的局部变量，靠闭包捕获——676 行的函数里挂着
// 八个可变状态，改任何一个接口都要通读全篇，也没法单独测某个 handler。
// 现在依赖是显式的：谁需要什么，看字段就知道；handler 是方法，可以直接用
// httptest 喂一个假的 hub / store 进来。
type server struct {
	varDir  string
	hub     *Hub
	store   *Store // 可能为 nil：历史库打不开时实时监控照常工作
	peers   *PeerTracker
	dom     *DomainCache
	sniffer *dnsSniffer
	geo     *GeoDB
	geoJob  *GeoJob
	fw      *Firewall
	fwPath  string
	alerts  *AlertEngine
	stat    *StatSampler
	dc      *cache
}

// routes 按领域分组注册所有接口，外面再套一层网关前缀裁剪。
//
// 分组不是为了好看，是为了「加一个接口时只需要看一个文件」：
// 观测类进 api_traffic.go，外联/拦截进 api_guard.go，其余进 api_misc.go。
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	s.routeTraffic(mux)
	s.routeGuard(mux)
	s.routeMisc(mux)
	return stripGatewayPrefix(mux)
}

// stripGatewayPrefix 处理 fnOS 统一网关的前缀。
//
// 网关不会剥掉 app/ui/config 里的 gatewayPrefix，所以进来的是
// /app/fnnetmon/api/xxx。这里统一裁掉再交给 mux。
// 兜底逻辑：无论前面挂了几层前缀，只要路径里有 /api/ 就按最后一段走接口——
// 这样即使网关以后改了前缀规则，接口也不会 404。
func stripGatewayPrefix(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/app/fnnetmon") {
			p = strings.TrimPrefix(p, "/app/fnnetmon")
			if p == "" {
				p = "/"
			}
			r2 := r.Clone(r.Context())
			r2.URL.Path = p
			mux.ServeHTTP(w, r2)
			return
		}
		if i := strings.LastIndex(p, "/api/"); i > 0 {
			r2 := r.Clone(r.Context())
			r2.URL.Path = p[i:]
			mux.ServeHTTP(w, r2)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// ---- Unix socket 的 Host 兼容层 ----
//
// 点桌面图标一直报 400 Bad Request 的根因在这里：fnOS 网关通过 app.sock
// 转发时不带 Host，或把 Host 写成 socket 路径（含 /）。Go 的 net/http 在
// **解析请求行/头部** 时就拒绝，返回
//
//	"400 Bad Request: missing required Host header" / "malformed Host header"
//
// handler 根本没机会执行。同样用 gatewaySocket 的清理精灵等应用没事，
// 是因为它们的后端对 Host 宽容，不是配置写错了。
//
// 只包 Unix socket 这一条入口：TCP 直连不受影响。补的是「合法但没给出」的
// Host，不碰路径、不碰 body；非 HTTP 流量和读了一半的请求头直接原样放行。
type hostFixListener struct{ net.Listener }

func (l hostFixListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &hostFixConn{Conn: c}, nil
}

type hostFixConn struct {
	net.Conn
	done bool
}

func (c *hostFixConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if c.done || n < 16 {
		return n, err
	}
	c.done = true
	fixed, ok := fixRequestHost(p[:n])
	if !ok || len(fixed) > len(p) {
		return n, err
	}
	copy(p, fixed)
	return len(fixed), err
}

// fixRequestHost 重写第一个请求的头部：没有合法 Host 就补一个。
// 返回 false 表示「不该动」，调用方原样透传。
func fixRequestHost(b []byte) ([]byte, bool) {
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 || !isHTTPRequestLine(b[:end]) {
		return nil, false
	}
	lines := bytes.Split(b[:end], []byte("\r\n"))
	out := make([]byte, 0, len(b)+32)
	out = append(out, lines[0]...)
	hasHost := false
	for _, ln := range lines[1:] {
		if len(ln) >= 5 && bytes.EqualFold(ln[:5], []byte("Host:")) {
			// 非法 Host（网关把 socket 路径塞进来）直接丢掉，别让 Go 再拒一次
			if validHostValue(strings.TrimSpace(string(ln[5:]))) {
				hasHost = true
				out = append(out, '\r', '\n')
				out = append(out, ln...)
			}
			continue
		}
		out = append(out, '\r', '\n')
		out = append(out, ln...)
	}
	if !hasHost {
		out = append(out, []byte("\r\nHost: localhost")...)
	}
	out = append(out, []byte("\r\n\r\n")...)
	out = append(out, b[end+4:]...) // 可能带着 body 的前几个字节，原样保留
	return out, true
}

func isHTTPRequestLine(b []byte) bool {
	s := string(b)
	for _, m := range [...]string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH "} {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}

// validHostValue 用和 net/http 的 httpguts.ValidHostHeader 一致的字符集，
// 宁可多补一个 Host，也别把非法值留给 Go 去 400。
func validHostValue(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte(".-_~%!$&'()*+,;=:@[]", c) >= 0:
		default:
			return false
		}
	}
	return true
}
