package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

type AccessPolicy struct {
	AllowCIDRs []string `json:"allow_cidrs"`
	DenyCIDRs  []string `json:"deny_cidrs"`
}
type TargetPolicy struct {
	Allow        []string `json:"allow"`
	Deny         []string `json:"deny"`
	DeniedAction string   `json:"denied_action"`
}
type AuthConfig struct {
	Type        string `json:"type"`
	UsernameEnv string `json:"username_env,omitempty"`
	PasswordEnv string `json:"password_env,omitempty"`
	TokenEnv    string `json:"token_env,omitempty"`
}
type Upstream struct {
	Name    string     `json:"name"`
	Address string     `json:"address"`
	TLS     string     `json:"tls"`
	Auth    AuthConfig `json:"auth"`
}
type Route struct {
	Domain   string `json:"domain"`
	Upstream string `json:"upstream"`
}
type Limits struct {
	MaxMessageBytes int64 `json:"max_message_bytes"`
	MaxRecipients   int   `json:"max_recipients"`
	MaxConnections  int   `json:"max_connections"`
	TimeoutSeconds  int   `json:"timeout_seconds"`
}
type Config struct {
	SMTPListen      string       `json:"smtp_listen"`
	AdminListen     string       `json:"admin_listen"`
	AdminAllowCIDRs []string     `json:"admin_allow_cidrs"`
	Domain          string       `json:"domain"`
	Mode            string       `json:"mode"`
	Access          AccessPolicy `json:"access"`
	AllowedSenders  []string     `json:"allowed_senders"`
	Targets         TargetPolicy `json:"targets"`
	Upstreams       []Upstream   `json:"upstreams"`
	Routes          []Route      `json:"routes"`
	DefaultUpstream string       `json:"default_upstream"`
	Limits          Limits       `json:"limits"`
}

func DefaultConfig() Config {
	return Config{SMTPListen: "127.0.0.1:12525", AdminListen: "127.0.0.1:16882", Domain: "pabal.local", Mode: "discard", Access: AccessPolicy{AllowCIDRs: []string{"127.0.0.1/32", "::1/128"}}, Targets: TargetPolicy{DeniedAction: "reject"}, Limits: Limits{MaxMessageBytes: 25 << 20, MaxRecipients: 50, MaxConnections: 20, TimeoutSeconds: 60}}
}
func normalizeConfig(c Config) Config {
	c.Upstreams = append([]Upstream(nil), c.Upstreams...)
	if c.Mode == "" {
		c.Mode = "discard"
	}
	if c.Targets.DeniedAction == "" {
		c.Targets.DeniedAction = "reject"
	}
	for i := range c.Upstreams {
		if c.Upstreams[i].TLS == "" {
			c.Upstreams[i].TLS = "starttls"
		}
		if c.Upstreams[i].Auth.Type == "" {
			c.Upstreams[i].Auth.Type = "none"
		}
	}
	return c
}
func cloneConfig(c Config) Config {
	b, _ := json.Marshal(c)
	var copy Config
	_ = json.Unmarshal(b, &copy)
	return copy
}
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	f, err := os.Open(path)
	if err != nil {
		return c, errors.New("cannot open configuration")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, errors.New("invalid configuration JSON")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("configuration must contain one JSON object")
	}
	c = normalizeConfig(c)
	return c, ValidateConfig(c)
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validMailbox(s string) bool {
	a, e := mail.ParseAddress(s)
	return e == nil && a.Address == s && strings.IndexFunc(s, func(r rune) bool { return r > 127 }) < 0 && !strings.ContainsAny(s, "\r\n")
}
func validDomain(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, "\r\n\t @/:[]") || strings.IndexFunc(s, func(r rune) bool { return r > 127 }) >= 0 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func validPattern(p string) bool {
	if strings.HasPrefix(p, "@") {
		return validDomain(p[1:])
	}
	return validMailbox(p)
}
func ValidateConfig(c Config) error {
	c = normalizeConfig(c)
	if c.Mode != "discard" && c.Mode != "relay" {
		return errors.New("mode must be discard or relay")
	}
	if !validDomain(c.Domain) {
		return errors.New("invalid relay domain")
	}
	for _, addr := range []string{c.SMTPListen, c.AdminListen} {
		if _, _, e := net.SplitHostPort(addr); e != nil {
			return errors.New("invalid listen address")
		}
	}
	if c.Targets.DeniedAction != "reject" && c.Targets.DeniedAction != "discard" {
		return errors.New("denied_action must be reject or discard")
	}
	for _, list := range [][]string{c.Access.AllowCIDRs, c.Access.DenyCIDRs, c.AdminAllowCIDRs} {
		for _, cidr := range list {
			p, e := netip.ParsePrefix(cidr)
			if e != nil || p.Bits() == 0 || p.Addr().Is4In6() {
				return errors.New("invalid CIDR or catch-all network")
			}
		}
	}
	if len(c.Access.AllowCIDRs) == 0 {
		return errors.New("at least one SMTP allowed CIDR is required")
	}
	for _, s := range c.AllowedSenders {
		if !validMailbox(s) {
			return errors.New("invalid allowed sender")
		}
	}
	for _, list := range [][]string{c.Targets.Allow, c.Targets.Deny} {
		for _, p := range list {
			if !validPattern(p) {
				return errors.New("invalid recipient pattern")
			}
		}
	}
	l := c.Limits
	if l.MaxMessageBytes < 1 || l.MaxMessageBytes > 50<<20 || l.MaxRecipients < 1 || l.MaxRecipients > 100 || l.MaxConnections < 1 || l.MaxConnections > 100 || l.TimeoutSeconds < 1 || l.TimeoutSeconds > 120 {
		return errors.New("invalid resource limits")
	}
	names := map[string]bool{}
	for _, u := range c.Upstreams {
		if !validDomain(u.Name) || names[u.Name] {
			return errors.New("invalid or duplicate upstream name")
		}
		names[u.Name] = true
		host, port, e := net.SplitHostPort(u.Address)
		if e != nil || host == "" || port == "" {
			return errors.New("invalid upstream address")
		}
		if u.TLS != "starttls" && u.TLS != "tls" && u.TLS != "none" {
			return errors.New("invalid upstream TLS mode")
		}
		if u.TLS == "none" {
			ip, e := netip.ParseAddr(host)
			if e != nil || !ip.Unmap().IsLoopback() {
				return errors.New("plaintext upstream requires literal loopback address")
			}
			if u.Auth.Type != "none" {
				return errors.New("plaintext upstream cannot use authentication")
			}
		}
		a := u.Auth
		switch a.Type {
		case "none":
			if a.UsernameEnv != "" || a.PasswordEnv != "" || a.TokenEnv != "" {
				return errors.New("none auth cannot reference credentials")
			}
		case "plain", "login":
			if !envName.MatchString(a.UsernameEnv) || !envName.MatchString(a.PasswordEnv) || a.TokenEnv != "" {
				return errors.New("password auth requires username/password environment references")
			}
		case "oauth2":
			if !envName.MatchString(a.UsernameEnv) || !envName.MatchString(a.TokenEnv) || a.PasswordEnv != "" {
				return errors.New("oauth2 requires username/token environment references")
			}
		default:
			return errors.New("invalid upstream authentication type")
		}
	}
	if c.DefaultUpstream != "" && !names[c.DefaultUpstream] {
		return errors.New("unknown default upstream")
	}
	domains := map[string]bool{}
	for _, r := range c.Routes {
		d := strings.ToLower(r.Domain)
		if !validDomain(d) || domains[d] || !names[r.Upstream] {
			return errors.New("invalid or duplicate route")
		}
		domains[d] = true
	}
	if c.Mode == "relay" && c.DefaultUpstream == "" && len(c.Routes) == 0 {
		return errors.New("relay mode requires a default upstream or routes")
	}
	return nil
}
func containsIP(list []string, ip netip.Addr) bool {
	for _, s := range list {
		p, e := netip.ParsePrefix(s)
		if e == nil && p.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}
func accessAllowed(c Config, ip netip.Addr) bool {
	return !containsIP(c.Access.DenyCIDRs, ip) && containsIP(c.Access.AllowCIDRs, ip)
}
func patternMatches(p, address string) bool {
	if strings.HasPrefix(p, "@") {
		_, d, ok := strings.Cut(address, "@")
		return ok && strings.EqualFold(d, p[1:])
	}
	pl, pd, ok := strings.Cut(p, "@")
	al, ad, ao := strings.Cut(address, "@")
	return ok && ao && pl == al && strings.EqualFold(pd, ad)
}
func recipientAllowed(c Config, address string) bool {
	for _, p := range c.Targets.Deny {
		if patternMatches(p, address) {
			return false
		}
	}
	if len(c.Targets.Allow) == 0 {
		return true
	}
	for _, p := range c.Targets.Allow {
		if patternMatches(p, address) {
			return true
		}
	}
	return false
}
func selectUpstream(c Config, address string) (Upstream, bool) {
	_, domain, _ := strings.Cut(address, "@")
	name := c.DefaultUpstream
	for _, r := range c.Routes {
		if strings.EqualFold(r.Domain, domain) {
			name = r.Upstream
			break
		}
	}
	for _, u := range c.Upstreams {
		if u.Name == name {
			return u, true
		}
	}
	return Upstream{}, false
}
