// xsec · 小神 桌面安全工具箱 (防御 / 只读 / 跨平台)
// 仅防御性巡检: 资产清点/配置审计/泄密排查/TLS与头部检查; 无漏洞利用/爆破/提权。
//   xsec list ; xsec run <模块|all> [目标]
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

type Finding struct{ Level, Msg string }
type Module struct {
	Name, Desc string
	Run        func(target string) []Finding
}

var registry = map[string]Module{}

func reg(m Module) { registry[m.Name] = m }
func infoF(f string, a ...any) Finding { return Finding{"INFO", fmt.Sprintf(f, a...)} }
func warnF(f string, a ...any) Finding { return Finding{"WARN", fmt.Sprintf(f, a...)} }
func badF(f string, a ...any) Finding  { return Finding{"FAIL", fmt.Sprintf(f, a...)} }

func init() {
	reg(Module{"sys.info", "操作系统与运行环境清点", func(t string) []Finding {
		host, _ := os.Hostname()
		return []Finding{infoF("OS=%s/%s", runtime.GOOS, runtime.GOARCH),
			infoF("主机=%s CPU核=%d Go=%s", host, runtime.NumCPU(), runtime.Version())}
	}})
}

var secretEnv = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|pwd|credential|api)`)
var longValue = regexp.MustCompile(`^[A-Za-z0-9_\-+/=]{16,}$`)

func init() {
	reg(Module{"audit.env", "环境变量中的疑似密钥/口令", func(t string) []Finding {
		var f []Finding
		for _, kv := range os.Environ() {
			i := strings.Index(kv, "=")
			k, v := kv[:i], kv[i+1:]
			u := strings.ToUpper(k)
			if u == "PWD" || u == "OLDPWD" { continue }
			if secretEnv.MatchString(k) && longValue.MatchString(v) {
				f = append(f, warnF("环境变量 %s 疑似含敏感凭据(长度%d)", k, len(v)))
			}
		}
		if len(f) == 0 { f = append(f, infoF("环境变量未发现明显硬编码凭据")) }
		return f
	}})
}

func init() {
	reg(Module{"net.interfaces", "本机网卡与地址清点", func(t string) []Finding {
		ifs, err := net.Interfaces()
		if err != nil { return []Finding{badF("%v", err)} }
		var f []Finding
		for _, it := range ifs {
			if it.Flags&net.FlagUp == 0 { continue }
			addrs, _ := it.Addrs()
			var as []string
			for _, a := range addrs { as = append(as, a.String()) }
			f = append(f, infoF("%s %s %s", it.Name, it.HardwareAddr, strings.Join(as, ",")))
		}
		return f
	}})
}

func init() {
	reg(Module{"net.tls", "目标主机 TLS 证书与协议检查", func(host string) []Finding {
		if host == "" { return []Finding{warnF("用法: run net.tls example.com:443")} }
		if !strings.Contains(host, ":") { host += ":443" }
		d := &net.Dialer{Timeout: 6 * time.Second}
		conn, err := tls.DialWithDialer(d, "tcp", host, &tls.Config{InsecureSkipVerify: true})
		if err != nil { return []Finding{badF("连接失败: %v", err)} }
		defer conn.Close()
		var f []Finding
		s := conn.ConnectionState()
		f = append(f, infoF("版本=%s 套件=%s", tlsVer(s.Version), tls.CipherSuiteName(s.CipherSuite)))
		for _, c := range s.PeerCertificates {
			f = append(f, infoF("证书 %s 到期=%s", c.Subject.CommonName, c.NotAfter.Format("2006-01-02")))
			if time.Now().After(c.NotAfter) { f = append(f, badF("证书已过期")) } else if time.Until(c.NotAfter) < 30*24*time.Hour { f = append(f, warnF("30天内到期")) }
		}
		return f
	}})
}

func tlsVer(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%x", v)
}

func init() {
	reg(Module{"web.headers", "站点安全响应头检查", func(u string) []Finding {
		if u == "" { return []Finding{warnF("用法: run web.headers https://站点")} }
		resp, err := (&http.Client{Timeout: 8 * time.Second}).Get(u)
		if err != nil { return []Finding{badF("%v", err)} }
		defer resp.Body.Close()
		want := []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"}
		f := []Finding{infoF("状态码=%d", resp.StatusCode)}
		for _, h := range want {
			if resp.Header.Get(h) == "" { f = append(f, warnF("缺少安全头: %s", h)) }
		}
		return f
	}})
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(secret|token|api[_-]?key)["'\s:=]+[A-Za-z0-9_\-]{16,}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{20,}`),
}
var skipDir = map[string]bool{".git": true, "node_modules": true, ".cache": true}

func init() {
	reg(Module{"fs.secrets", "目录内硬编码密钥/私钥排查", func(root string) []Finding {
		if root == "" { return []Finding{warnF("用法: run fs.secrets /项目目录")} }
		var f []Finding
		hits := 0
		filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				if d != nil && skipDir[d.Name()] { return filepath.SkipDir }
				return nil
			}
			if in, e := d.Info(); e == nil && in.Size() > 2_000_000 { return nil }
			b, e := os.ReadFile(p)
			if e != nil { return nil }
			for _, rx := range secretPatterns {
				if rx.Match(b) { f = append(f, badF("%s 命中 %s", p, short(rx.String()))); hits++; break }
			}
			return nil
		})
		if hits == 0 { f = append(f, infoF("未发现硬编码密钥")) }
		return f
	}})
}

func short(s string) string { if len(s) > 24 { return s[:24] + "..." }; return s }

func init() {
	reg(Module{"hardening.tips", "通用加固建议清单", func(t string) []Finding {
		return []Finding{
			infoF("启用磁盘加密并设置开机口令"),
			infoF("开启自动安全更新, 关闭多余服务与端口"),
			infoF("敏感账号启用多因素认证(MFA)"),
			infoF("使用密钥管理器, 禁止硬编码凭据"),
			infoF("站点强制 HTTPS+HSTS, 配置 CSP"),
			infoF("最小权限审计与 3-2-1 离线备份")}
	}})
}

func runModule(name, target string) {
	var mods []Module
	if name == "all" {
		keys := make([]string, 0, len(registry))
		for k := range registry { keys = append(keys, k) }
		sort.Strings(keys)
		for _, k := range keys { mods = append(mods, registry[k]) }
	} else {
		m, ok := registry[name]
		if !ok { fmt.Println("[!] 未知模块:", name); return }
		mods = append(mods, m)
	}
	for _, m := range mods {
		fmt.Printf("\n=== %s — %s ===\n", m.Name, m.Desc)
		for _, r := range m.Run(target) {
			mark := " "
			if r.Level == "WARN" { mark = "!" } else if r.Level == "FAIL" { mark = "x" }
			fmt.Printf("  [%s] %s\n", mark, r.Msg)
		}
	}
}

func main() {
	if len(os.Args) < 2 { usage(); return }
	switch os.Args[1] {
	case "list":
		keys := make([]string, 0, len(registry))
		for k := range registry { keys = append(keys, k) }
		sort.Strings(keys)
		fmt.Println("防御型安全模块:")
		for _, k := range keys { fmt.Printf("  %-14s %s\n", k, registry[k].Desc) }
	case "run":
		name, target := "all", ""
		if len(os.Args) >= 3 { name = os.Args[2] }
		if len(os.Args) >= 4 { target = os.Args[3] }
		runModule(name, target)
	default:
		usage()
	}
}

func usage() {
	fmt.Println(`xsec 小神桌面安全工具箱(防御/只读):
  xsec list
  xsec run <模块|all> [目标]
  加解密请使用同套件 xshenctl`)
}
