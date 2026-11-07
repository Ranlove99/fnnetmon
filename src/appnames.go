package main

import "strings"

// 内置的「应用包名 → 展示名」对照表。
//
// 这只是**最后一档**兜底，正常情况下用不到：
//
//  1. 先问 `appcenter-cli list`（应用中心自己维护的已装列表，最权威）
//  2. 再读 /var/apps/<pkg>/manifest 的 display_name
//  3. 再读 /var/apps/<pkg>/app/ui/config 的 title
//  4. 都没有，才查这张表
//  5. 连表里也没有，才显示包名本身
//
// 数据来源：
//   - 第三方应用取自已发布的 fpk 包 manifest（conversun/fnos-apps 汇总的 178 个应用），
//     所以这里的 key 就是真实的应用目录名，不是猜的。
//   - 官方内置应用只收了有真机实证的几个（见下），没有证据的一律不写：
//     宁可显示 trim.xxx，也不能编一个看起来对的名字。
//
// 这张表只在「应用中心 CLI 跑不起来 + manifest 也读不到」时生效，
// 比如应用目录被删了一半、或者权限不足。
var builtinAppNames = map[string]string{
	"1panel":              "1Panel",
	"Aellus":              "Aellus·局域网传输",
	"LitePan":             "LitePan",
	"Nvidia-Driver-580":   "NVIDIA Driver",
	"actual-budget":       "Actual Budget",
	"adguardhome":         "AdGuardHome",
	"alist":               "Alist",
	"ani-rss":             "ANI-RSS",
	"appflowy":            "AppFlowy",
	"arcane":              "Arcane",
	"aria2-next":          "Aria2 Next",
	"astrbot":             "AstrBot",
	"audiobookshelf":      "Audiobookshelf",
	"auto-bangumi":        "AutoBangumi",
	"bazarr":              "Bazarr",
	"beszel":              "Beszel",
	"bililive-go":         "Bililive-go",
	"blinko":              "Blinko",
	"calibre-web":         "Calibre-Web",
	"certimate":           "Certimate",
	"chinesesubfinder":    "ChineseSubFinder",
	"chromium":            "Chromium",
	"clamav":              "ClamAV",
	"clash-for-fnos":      "Clash for fnos",
	"clouddrive2":         "CloudDrive2",
	"cloudflared":         "Cloudflare Tunnel",
	"cloudreve":           "Cloudreve",
	"coolercontrol":       "CoolerControl",
	"copaw":               "CoPaw",
	"copyparty":           "CopyParty",
	"cowagent":            "CowAgent",
	"daidai-panel":        "Daidai Panel",
	"danmu-api":           "Danmu API",
	"ddns-go":             "DDNS-GO",
	"docsify":             "Docsify",
	"dpanel":              "DPanel",
	"duplicati":           "Duplicati",
	"easytier":            "EasyTier",
	"embyserver":          "Emby",
	"ente":                "Ente",
	"ezbookkeeping":       "EZBookkeeping",
	"feigram":             "Feigram",
	"filebrowser":         "FileBrowser",
	"fileview":            "Fileview",
	"firefox":             "Firefox",
	"fnmonitor":           "飞牛监控",
	"fnos-apps-store":     "fnOS Apps",
	"fnosoidcbridge":      "OIDC SSO Bridge",
	"fntvplus":            "Fntv-Plus",
	"forgejo":             "Forgejo",
	"freshrss":            "FreshRSS",
	"frigate":             "Frigate",
	"frps":                "FRP Server",
	"gitea":               "Gitea",
	"glance":              "Glance",
	"glances":             "Glances",
	"gopeed":              "Gopeed",
	"gotify":              "Gotify",
	"grafana":             "Grafana",
	"handbrake":           "HandBrake",
	"headscale":           "Headscale",
	"homarr":              "Homarr",
	"homeassistant":       "Home Assistant",
	"homebox":             "Homebox",
	"homepage":            "Homepage",
	"immich":              "Immich",
	"it-tools":            "IT-Tools",
	"jackett":             "Jackett",
	"jellyfin":            "Jellyfin",
	"jellyseerr":          "Jellyseerr",
	"jellystat":           "Jellystat",
	"kavita":              "Kavita",
	"kodbox":              "KodBox",
	"koel":                "Koel",
	"komari":              "Komari",
	"komga":               "Komga",
	"koodo-reader":        "Koodo Reader",
	"lanraragi":           "LANraragi",
	"librechat":           "LibreChat",
	"lidarr":              "Lidarr",
	"linkwarden":          "Linkwarden",
	"localai":             "LocalAI",
	"loki":                "Loki",
	"lucky":               "Lucky",
	"lyranest":            "LyraNest",
	"mail-archiver":       "Mail Archiver",
	"mattermost":          "Mattermost",
	"maxkb":               "MaxKB",
	"mealie":              "Mealie",
	"medusa":              "Medusa",
	"melody-hub":          "MelodyHub",
	"memos":               "Memos",
	"menote":              "MeNote",
	"metatube":            "MetaTube",
	"metube":              "MeTube",
	"miair-next":          "MiAir Next",
	"mihomo":              "Mihomo",
	"miniflux":            "Miniflux",
	"mosdns":              "MosDNS",
	"moviepilot":          "MoviePilot",
	"msf":                 "MSF",
	"n8n":                 "n8n",
	"nanobot":             "Nanobot",
	"navidrome":           "Navidrome",
	"netbird":             "NetBird",
	"netdata":             "Netdata",
	"next-ai-draw-io":     "Next AI Draw.io",
	"nextcloud":           "Nextcloud",
	"nginx-proxy-manager": "Nginx Proxy Manager",
	"nginx-ui":            "Nginx UI",
	"nginx-web":           "nginx-web",
	"nginxserver":         "Nginx",
	"niupic":              "NiuPic",
	"node-red":            "Node-RED",
	"ntfy":                "Ntfy",
	"obsidian":            "Obsidian",
	"ollama":              "Ollama",
	"ombi":                "Ombi",
	"open-webui":          "Open WebUI",
	"openlist":            "OpenList",
	"opensurge":           "OpenSurge",
	"paperless-ngx":       "Paperless-ngx",
	"penpot":              "Penpot",
	"photoprism":          "PhotoPrism",
	"picoclaw":            "PicoClaw",
	"pihole":              "Pi-hole",
	"plexmediaserver":     "Plex",
	"pocket-id":           "Pocket ID",
	"prometheus":          "Prometheus",
	"prowlarr":            "Prowlarr",
	"pushme-server":       "PushMe Server",
	"puter":               "Puter",
	"qBittorrent":         "qBittorrent",
	"qinglong":            "QingLong",
	"qwenpaw":             "QwenPaw",
	"radarr":              "Radarr",
	"rclone":              "Rclone",
	"reactive-resume":     "Reactive Resume",
	"readarr":             "Readarr",
	"rocketchat":          "Rocket.Chat",
	"rustdesk-server":     "RustDesk Server",
	"sabnzbd":             "SABnzbd",
	"sakurafrp":           "SakuraFrp",
	"seafile":             "Seafile",
	"seerr":               "Seerr",
	"siyuan":              "SiYuan 思源笔记",
	"smartdns":            "SmartDNS",
	"sonarr":              "Sonarr",
	"songloft":            "Songloft",
	"stirling-pdf":        "Stirling-PDF",
	"sub-store":           "Sub-Store",
	"suggestarr":          "SuggestArr",
	"sun-panel":           "Sun-Panel",
	"sunshine":            "Sunshine",
	"surface-battery":     "Surface 电池驱动",
	"surveyking":          "SurveyKing",
	"suwayomi":            "Suwayomi",
	"syncthing":           "Syncthing",
	"tailscale":           "Tailscale",
	"tautulli":            "Tautulli",
	"tinymediamanager":    "tinyMediaManager",
	"transmission":        "Transmission",
	"trim.music":          "音乐",
	"trim.photos":         "相册",
	"trim.vm":             "虚拟机",
	"uptime-kuma":         "Uptime Kuma",
	"vaultwarden":         "Vaultwarden",
	"verysync":            "Verysync",
	"vibenvr":             "VibeNVR",
	"vikunja":             "Vikunja",
	"visor":               "Visor",
	"wg-easy":             "WG-Easy",
	"wikijs":              "Wiki.js",
	"wizarr":              "Wizarr",
	"wolgoweb":            "WolGoWeb",
	"zeroclaw":            "ZeroClaw",
	"zerotier":            "ZeroTier",
	"zonefoundry-bridge":  "ZoneFoundry Bridge",
}

// builtinAppNamesLower 是上面那张表的小写索引，用来兜住大小写不一致：
// 目录名是 Mahjong，而 systemd 单元可能写成 mahjong.service。
var builtinAppNamesLower = func() map[string]string {
	m := make(map[string]string, len(builtinAppNames))
	for k, v := range builtinAppNames {
		m[strings.ToLower(k)] = v
	}
	return m
}()

// builtinName 查兜底表。查不到返回空。
//
// 除了原样和全小写，还会把 - 和 _ 归一成 . 再试一次：
// 应用目录叫 trim.photos，但它的可执行文件叫 trim-photos、
// systemd 单元也可能叫 trim-photos.service，归一之后才对得上。
func builtinName(key string) string {
	if key == "" {
		return ""
	}
	if v, ok := builtinAppNames[key]; ok {
		return v
	}
	low := strings.ToLower(key)
	if v, ok := builtinAppNamesLower[low]; ok {
		return v
	}
	if norm := strings.NewReplacer("-", ".", "_", ".").Replace(low); norm != low {
		if v, ok := builtinAppNamesLower[norm]; ok {
			return v
		}
	}
	return ""
}
