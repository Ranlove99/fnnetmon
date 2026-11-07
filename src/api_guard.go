package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
)

// routeGuard 注册「外联 + 拦截」的接口。
//
// 这两块放在一个文件里是有原因的：裁决（verdict）会顺手生成拦截规则，
// 撤销裁决会顺手删规则，忽略会连带清规则——它们是同一条链上的三环，
// 拆到两个文件里反而看不全。
func (s *server) routeGuard(mux *http.ServeMux) {
	mux.HandleFunc("/api/peers", s.handlePeers)
	mux.HandleFunc("/api/peers/verdict", s.handleVerdict)
	mux.HandleFunc("/api/peers/forget", s.handleForget)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/toggle", s.handleRuleToggle)
	mux.HandleFunc("/api/rules/delete", s.handleRuleDelete)
	mux.HandleFunc("/api/firewall", s.handleFirewall)
	mux.HandleFunc("/api/firewall/panic", s.handlePanic)
}

func (s *server) handlePeers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	list := s.peers.List(q.Get("private") == "1", q.Get("pending") == "1", q.Get("q"), limit)
	// 补应用名：外联页和连接页一样按「飞牛影视」显示，进程名放副行。
	// 容器条目直接用容器名（用户认得出的就是容器名）；
	// 宿主进程查不到（最近没流量）就空着，前端退回显示进程名。
	svcMap := s.hub.ProcServices()
	for i := range list {
		if list[i].Cont != "" {
			list[i].Svc = list[i].Cont
		} else {
			list[i].Svc = svcMap[list[i].Proc]
		}
	}
	jsonReply(w, map[string]any{
		"peers":   list,
		"pending": s.peers.Pending(),
		"total":   s.peers.Count(),
	}, 200)
}

// handleVerdict 处理「允许 / 阻止」。
//
// allow 只是记账；deny 会顺手生成一条拦截规则（防火墙可用时）。
// scope=domain 时按域名生成规则 —— 这是 CDN 场景下唯一正确的做法，
// 否则封掉的就是「当时解析到的那一个 IP」，换一个节点就绕过了。
func (s *server) handleVerdict(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proc    string `json:"proc"`
		IP      string `json:"ip"`
		Domain  string `json:"domain"`
		Scope   string `json:"scope"` // ip | domain
		Verdict string `json:"verdict"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 400)
		return
	}
	if req.Verdict != "allow" && req.Verdict != "deny" && req.Verdict != "" {
		jsonReply(w, map[string]string{"error": "verdict 只能是 allow / deny / 空"}, 400)
		return
	}
	if err := s.peers.SetVerdict(req.Proc, req.IP, req.Verdict); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 500)
		return
	}

	byDomain := req.Scope == "domain" && req.Domain != ""
	domain := normalizeDomain(req.Domain)
	p := s.peers.Get(req.Proc, req.IP)

	msg := "已记录"
	switch {
	case req.Verdict == "deny":
		if s.store == nil {
			msg = "已标记阻止，但历史库不可用，规则无法保存"
			break
		}
		if p == nil {
			msg = "已标记阻止，但对端记录已消失，无法生成规则"
			break
		}
		if p.Cgroup == "" {
			msg = "已标记阻止，但该进程没有 cgroup 路径，无法生成拦截规则"
			break
		}
		rule := Rule{
			Action: "deny", Proc: p.Proc, Cont: p.Cont, Cgroup: p.Cgroup,
			Enabled: true, Note: autoRuleNote,
		}
		if byDomain {
			if !validDomain(domain) {
				msg = "已标记阻止，但域名不合法，未生成规则"
				break
			}
			// 先解析一次：解析不出来就不建规则，免得留一条永远不生效的记录
			if _, err := s.dom.Resolve(domain); err != nil {
				msg = "已标记阻止，但域名解析失败（" + firstLine(err.Error()) + "），未生成规则"
				break
			}
			rule.Kind = "domain"
			rule.Domain = domain
		} else {
			rule.Kind = "ip"
			rule.IP = p.IP
		}
		id, err := s.store.AddRule(rule)
		if err != nil {
			msg = "已标记阻止，但保存规则失败：" + err.Error()
			break
		}
		reloadRules(s.store, s.fw)
		if byDomain {
			msg = "已按域名阻止，规则 #" + strconv.FormatInt(id, 10) + "（" + domain + "）"
		} else {
			msg = "已阻止并生成规则 #" + strconv.FormatInt(id, 10)
		}

	case req.Verdict == "" && s.store != nil:
		// 撤销裁决时把当时自动生成的那条规则一并清掉，
		// 否则会留下一条没人记得的拦截规则，排查时非常难找。
		// 域名规则和 IP 规则各查一次，因为不知道当初是哪一种。
		_ = s.store.DeleteAutoRules(req.Proc, req.IP, "")
		if p != nil && p.Domain != "" {
			_ = s.store.DeleteAutoRules(req.Proc, "", p.Domain)
		}
		reloadRules(s.store, s.fw)
		msg = "已撤销裁决，对应规则已清除"
	}
	jsonReply(w, map[string]any{"ok": true, "msg": msg, "fw": s.fw.Status()}, 200)
}

// handleForget 忽略：删掉记录，下次再连会重新被当成新外联。
func (s *server) handleForget(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Proc string `json:"proc"`
		IP   string `json:"ip"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 400)
		return
	}
	p := s.peers.Get(req.Proc, req.IP)
	if err := s.peers.Forget(req.Proc, req.IP); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 500)
		return
	}
	if s.store != nil {
		_ = s.store.DeleteAutoRules(req.Proc, req.IP, "")
		if p != nil && p.Domain != "" {
			_ = s.store.DeleteAutoRules(req.Proc, "", p.Domain)
		}
		reloadRules(s.store, s.fw)
	}
	jsonReply(w, map[string]any{"ok": true}, 200)
}

func (s *server) handleRules(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		jsonReply(w, map[string]string{"error": "历史库不可用，规则无法保存"}, 503)
		return
	}
	if r.Method == http.MethodPost {
		var req Rule
		if err := readJSON(r, &req); err != nil {
			jsonReply(w, map[string]string{"error": err.Error()}, 400)
			return
		}
		if req.Action != "allow" && req.Action != "deny" {
			req.Action = "deny"
		}
		if req.Cgroup == "" {
			jsonReply(w, map[string]string{"error": "缺少 cgroup 路径，无法按进程匹配"}, 400)
			return
		}
		if req.Kind == "domain" {
			req.Domain = normalizeDomain(req.Domain)
			if !validDomain(req.Domain) {
				jsonReply(w, map[string]string{"error": "非法域名：请填 example.com 这种形式"}, 400)
				return
			}
			// 建规则时就解析一次，否则这条规则要到下一个刷新周期才生效，
			// 用户会以为「点了没反应」。
			if _, err := s.dom.Resolve(req.Domain); err != nil {
				jsonReply(w, map[string]string{
					"error": "域名解析失败：" + firstLine(err.Error()),
				}, 400)
				return
			}
			req.IP = ""
		} else {
			req.Kind = "ip"
			req.Domain = ""
			if req.IP != "" {
				if err := validCIDR(req.IP); err != nil {
					jsonReply(w, map[string]string{"error": err.Error()}, 400)
					return
				}
			}
		}
		id, err := s.store.AddRule(req)
		if err != nil {
			jsonReply(w, map[string]string{"error": err.Error()}, 500)
			return
		}
		reloadRules(s.store, s.fw)
		jsonReply(w, map[string]any{"ok": true, "id": id, "fw": s.fw.Status()}, 200)
		return
	}
	rules, err := s.store.ListRules()
	if err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 500)
		return
	}
	// 域名规则当前解析到多少个地址，直接按缓存填上。
	// 不填的话，拦截没启用时 Reload 不会走 renderRules，界面上永远显示「尚未解析」。
	fillRuleIPs(rules, s.dom)
	jsonReply(w, map[string]any{"rules": rules, "fw": s.fw.Status()}, 200)
}

func (s *server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      int64 `json:"id"`
		Enabled bool  `json:"enabled"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 400)
		return
	}
	if s.store == nil {
		jsonReply(w, map[string]string{"error": "历史库不可用"}, 503)
		return
	}
	if err := s.store.SetRuleEnabled(req.ID, req.Enabled); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 500)
		return
	}
	reloadRules(s.store, s.fw)
	jsonReply(w, map[string]any{"ok": true, "fw": s.fw.Status()}, 200)
}

func (s *server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int64 `json:"id"`
	}
	if err := readJSON(r, &req); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 400)
		return
	}
	if s.store == nil {
		jsonReply(w, map[string]string{"error": "历史库不可用"}, 503)
		return
	}
	if err := s.store.DeleteRule(req.ID); err != nil {
		jsonReply(w, map[string]string{"error": err.Error()}, 500)
		return
	}
	reloadRules(s.store, s.fw)
	jsonReply(w, map[string]any{"ok": true, "fw": s.fw.Status()}, 200)
}

func (s *server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req struct {
			Enforce bool `json:"enforce"`
		}
		if err := readJSON(r, &req); err != nil {
			jsonReply(w, map[string]string{"error": err.Error()}, 400)
			return
		}
		var rules []Rule
		if s.store != nil {
			rules, _ = s.store.ListRules()
		}
		if err := s.fw.SetEnforce(req.Enforce, rules); err != nil {
			jsonReply(w, map[string]any{"error": err.Error(), "fw": s.fw.Status()}, 500)
			return
		}
		_ = fwStateSave(s.fwPath, req.Enforce)
		jsonReply(w, map[string]any{"ok": true, "fw": s.fw.Status()}, 200)
		return
	}
	jsonReply(w, s.fw.Status(), 200)
}

// handlePanic 紧急停止：一键删表，不等任何确认。
//
// 这是整个软件里唯一「不需要二次确认」的写操作，因为它的使用场景
// 就是「网络已经断了，先恢复再说」。
func (s *server) handlePanic(w http.ResponseWriter, r *http.Request) {
	_ = s.fw.Clear()
	_ = fwStateSave(s.fwPath, false)
	fmt.Fprintf(os.Stderr, "[fnnetmon] PANIC: firewall cleared by request\n")
	jsonReply(w, map[string]any{"ok": true, "fw": s.fw.Status()}, 200)
}
