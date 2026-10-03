package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var dashboardAssets embed.FS

type dashboard struct {
	app       *App
	store     *Store
	templates *template.Template
	mutation  sync.Mutex
}
type clientView struct {
	ClientLabel
	Count       int
	Last        string
	Denied      bool
	ExactDenied bool
}
type dashboardView struct {
	Section, Title, Description, Token, Notice, Error, Q, Status, Category, DetailID string
	Page, Pages, Count                                                               int
	Events                                                                           []Event
	Clients                                                                          []clientView
	Changes                                                                          []Change
	Stats                                                                            map[string]int
	Config                                                                           map[string]any
	Last                                                                             string
	Prev, Next, Export                                                               string
	Selected                                                                         *Event
}

func NewDashboard(app *App, store *Store) http.Handler {
	funcs := template.FuncMap{"join": func(v []string) string { return strings.Join(v, ", ") }, "pretty": func(v any) string { b, _ := json.MarshalIndent(v, "", "  "); return string(b) }, "lines": func(v any) string {
		b, _ := json.Marshal(v)
		var list []string
		_ = json.Unmarshal(b, &list)
		return strings.Join(list, "\n")
	}, "utc": func(v string) string {
		d, e := time.Parse(time.RFC3339Nano, v)
		if e != nil {
			return v
		}
		return d.UTC().Format("2006-01-02 15:04:05 UTC")
	}, "path": url.PathEscape}
	t := template.Must(template.New("dashboard").Funcs(funcs).ParseFS(dashboardAssets, "web/dashboard.html"))
	return &dashboard{app: app, store: store, templates: t}
}
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	return ip.String()
}
func (d *dashboard) allowed(r *http.Request) bool {
	ip := net.ParseIP(remoteIP(r))
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	b, _ := json.Marshal(d.app.Snapshot())
	var cfg map[string]json.RawMessage
	_ = json.Unmarshal(b, &cfg)
	var cidrs []string
	_ = json.Unmarshal(cfg["admin_allow_cidrs"], &cidrs)
	for _, value := range cidrs {
		_, network, err := net.ParseCIDR(value)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
func (d *dashboard) session(w http.ResponseWriter, r *http.Request) string {
	key := []byte(d.store.Secret())
	cookie, err := r.Cookie("pabal_session")
	if err == nil {
		parts := strings.Split(cookie.Value, ".")
		if len(parts) == 3 {
			expiry, e := strconv.ParseInt(parts[1], 10, 64)
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(parts[0] + "." + parts[1]))
			expected := hex.EncodeToString(mac.Sum(nil))
			if e == nil && expiry > time.Now().Unix() && expiry <= time.Now().Add(25*time.Hour).Unix() && hmac.Equal([]byte(parts[2]), []byte(expected)) {
				return parts[0]
			}
		}
	}
	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		http.Error(w, "Unable to initialize session", 503)
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(nonce)
	value := token + "." + strconv.FormatInt(time.Now().Add(24*time.Hour).Unix(), 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	value += "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{Name: "pabal_session", Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 86400})
	return token
}
func (d *dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'")
	if !d.allowed(r) {
		http.Error(w, "Management access denied", 403)
		return
	}
	if r.URL.Path == "/static/admin.css" {
		b, _ := dashboardAssets.ReadFile("web/admin.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(b)
		return
	}
	if r.URL.Path == "/static/admin.js" {
		b, _ := dashboardAssets.ReadFile("web/admin.js")
		w.Header().Set("Content-Type", "application/javascript")
		w.Write(b)
		return
	}
	if r.URL.Path == "/livez" || r.URL.Path == "/readyz" {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", 405)
			return
		}
		w.Write([]byte("OK"))
		return
	}
	token := d.session(w, r)
	if token == "" {
		return
	}
	if r.Method == http.MethodPost {
		origin := r.Header.Get("Origin")
		if origin != "" {
			u, e := url.Parse(origin)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if e != nil || u.Host != r.Host || u.Scheme != scheme {
				http.Error(w, "Cross-site request rejected", 403)
				return
			}
		}
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Cross-site request rejected", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		if r.ParseForm() != nil {
			http.Error(w, "Invalid form", 400)
			return
		}
		if !hmac.Equal([]byte(r.FormValue("csrf")), []byte(token)) {
			http.Error(w, "Invalid CSRF token", 403)
			return
		}
		d.mutate(w, r, token)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.URL.Path == "/export/events.csv" {
		d.export(w, r)
		return
	}
	d.render(w, r, token, "", "")
}
func bounded(value string, defaultValue, minimum, maximum int) int {
	n, e := strconv.Atoi(value)
	if e != nil {
		return defaultValue
	}
	if n < minimum {
		return minimum
	}
	if n > maximum {
		return maximum
	}
	return n
}
func filteredEvents(events []Event, r *http.Request) []Event {
	q := strings.ToLower(r.URL.Query().Get("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	status := r.URL.Query().Get("status")
	client := r.URL.Query().Get("client")
	rows := []Event{}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if status != "" && status != e.Status {
			continue
		}
		if client != "" && e.ClientIP != client {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(e.ID+" "+e.ClientIP+" "+e.Sender+" "+strings.Join(e.Recipients, " ")+" "+e.Upstream), q) {
			continue
		}
		rows = append(rows, e)
	}
	return rows
}
func (d *dashboard) render(w http.ResponseWriter, r *http.Request, token, notice, errText string) {
	section := strings.Trim(r.URL.Path, "/")
	if section == "" {
		section = "overview"
	}
	valid := map[string]string{"overview": "Overview", "events": "Message events", "clients": "Registered clients", "settings": "Relay settings", "changes": "Management changes"}
	detailID := ""
	if strings.HasPrefix(section, "events/") {
		detailID = strings.TrimPrefix(section, "events/")
		section = "events"
	}
	title, ok := valid[section]
	if !ok {
		http.NotFound(w, r)
		return
	}
	events := d.store.Events()
	rows := filteredEvents(events, r)
	stats := map[string]int{}
	for _, e := range events {
		stats[e.Status]++
	}
	last := ""
	if len(events) > 0 {
		last = events[len(events)-1].Time
	}
	cfgBytes, _ := json.Marshal(d.app.Snapshot())
	cfg := map[string]any{}
	_ = json.Unmarshal(cfgBytes, &cfg)
	page := bounded(r.URL.Query().Get("page"), 1, 1, 100000)
	per := bounded(r.URL.Query().Get("per_page"), 25, 10, 100)
	v := dashboardView{Section: section, Title: title, Description: "Metadata-only SMTP testing and relay control.", Token: token, Notice: notice, Error: errText, Q: r.URL.Query().Get("q"), Status: r.URL.Query().Get("status"), Category: r.URL.Query().Get("category"), Page: page, Stats: stats, Config: cfg, Last: last, Count: len(rows), DetailID: detailID}
	if detailID != "" {
		for _, e := range events {
			if e.ID == detailID {
				copy := e
				v.Selected = &copy
			}
		}
		if v.Selected == nil {
			http.NotFound(w, r)
			return
		}
	}
	if section == "overview" {
		if len(rows) > 5 {
			rows = rows[:5]
		}
		v.Events = rows
	} else if section == "events" {
		v.Count = len(rows)
		v.Pages = (len(rows) + per - 1) / per
		if v.Pages < 1 {
			v.Pages = 1
		}
		start := (page - 1) * per
		if start < len(rows) {
			end := start + per
			if end > len(rows) {
				end = len(rows)
			}
			v.Events = rows[start:end]
		}
	}
	if section == "clients" {
		labels := d.store.Clients()
		inventory := map[string]clientView{}
		for ip, label := range labels {
			inventory[ip] = clientView{ClientLabel: label}
		}
		for _, e := range events {
			if e.ClientIP == "" {
				continue
			}
			entry := inventory[e.ClientIP]
			entry.IP = e.ClientIP
			entry.Count++
			entry.Last = e.Time
			inventory[e.ClientIP] = entry
		}
		for _, entry := range inventory {
			address := net.ParseIP(entry.IP)
			for _, cidr := range d.app.Snapshot().Access.DenyCIDRs {
				_, network, err := net.ParseCIDR(cidr)
				if err == nil && address != nil && network.Contains(address) {
					entry.Denied = true
					ones, bits := network.Mask.Size()
					if ones == bits {
						entry.ExactDenied = true
					}
				}
			}
			if v.Category != "" && entry.Category != v.Category {
				continue
			}
			if v.Q != "" && !strings.Contains(strings.ToLower(entry.IP+" "+entry.Name+" "+entry.Category), strings.ToLower(v.Q)) {
				continue
			}
			v.Clients = append(v.Clients, entry)
		}
		sort.Slice(v.Clients, func(i, j int) bool { return v.Clients[i].IP < v.Clients[j].IP })
		v.Count = len(v.Clients)
		v.Pages = (v.Count + per - 1) / per
		if v.Pages < 1 {
			v.Pages = 1
		}
		start := (page - 1) * per
		if start >= len(v.Clients) {
			v.Clients = nil
		} else {
			end := start + per
			if end > len(v.Clients) {
				end = len(v.Clients)
			}
			v.Clients = v.Clients[start:end]
		}
	}
	if section == "changes" {
		changes := d.store.Changes()
		for i := len(changes) - 1; i >= 0; i-- {
			v.Changes = append(v.Changes, changes[i])
		}
		v.Count = len(v.Changes)
		v.Pages = (v.Count + per - 1) / per
		if v.Pages < 1 {
			v.Pages = 1
		}
		start := (page - 1) * per
		if start >= v.Count {
			v.Changes = nil
		} else {
			end := start + per
			if end > v.Count {
				end = v.Count
			}
			v.Changes = v.Changes[start:end]
		}
	}
	params := r.URL.Query()
	params.Set("page", strconv.Itoa(page-1))
	if page > 1 {
		v.Prev = r.URL.Path + "?" + params.Encode()
	}
	params.Set("page", strconv.Itoa(page+1))
	if page < v.Pages {
		v.Next = r.URL.Path + "?" + params.Encode()
	}
	params.Del("page")
	v.Export = "/export/events.csv?" + params.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.templates.ExecuteTemplate(w, "dashboard.html", v); err != nil { /* Header may already have been sent; no private error details are exposed. */
	}
}
func textLines(s string) []string {
	var out []string
	for _, v := range strings.Split(s, "\n") {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
func (d *dashboard) mutate(w http.ResponseWriter, r *http.Request, token string) {
	d.mutation.Lock()
	defer d.mutation.Unlock()
	if r.URL.Path == "/clients/policy" {
		ip := net.ParseIP(strings.TrimSpace(r.FormValue("ip")))
		if ip == nil {
			http.Error(w, "Invalid client IP", 400)
			return
		}
		original := d.app.Snapshot()
		next := cloneConfig(original)
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		cidr := ip.String() + "/" + strconv.Itoa(bits)
		action := r.FormValue("action")
		if action != "block" && action != "unblock" {
			http.Error(w, "Invalid client policy action", 400)
			return
		}
		kept := []string{}
		found := false
		for _, existing := range next.Access.DenyCIDRs {
			_, network, err := net.ParseCIDR(existing)
			exact := false
			if err == nil {
				ones, maskBits := network.Mask.Size()
				exact = ones == maskBits && network.Contains(ip)
			}
			if exact {
				found = true
				if action == "unblock" {
					continue
				}
			}
			kept = append(kept, existing)
		}
		if action == "block" && !found {
			kept = append(kept, cidr)
		}
		next.Access.DenyCIDRs = kept
		if err := d.app.Update(next); err != nil {
			http.Error(w, "Unable to update client policy", 400)
			return
		}
		if err := d.store.ConfigChange(d.app.Snapshot(), remoteIP(r)); err != nil {
			_ = d.app.Update(original)
			http.Error(w, "Unable to persist policy", 503)
			return
		}
		http.Redirect(w, r, "/clients", http.StatusSeeOther)
		return
	}
	if r.URL.Path == "/clients" {
		ip := net.ParseIP(strings.TrimSpace(r.FormValue("ip")))
		if ip == nil {
			d.render(w, r, token, "", "Enter a valid IPv4 or IPv6 address.")
			return
		}
		label := ClientLabel{IP: ip.String(), Name: strings.TrimSpace(r.FormValue("name")), Category: strings.TrimSpace(r.FormValue("category")), Note: strings.TrimSpace(r.FormValue("note")), UpdatedAt: time.Now().UTC().Format(time.RFC3339)}
		if len(label.Name) > 100 || len(label.Category) > 80 || len(label.Note) > 2000 {
			http.Error(w, "Client fields exceed the allowed length", 400)
			return
		}
		if err := d.store.SaveClient(label, remoteIP(r)); err != nil {
			http.Error(w, "Unable to save client metadata", 503)
			return
		}
		d.render(w, r, token, "Client metadata saved.", "")
		return
	}
	if r.URL.Path != "/settings" {
		http.NotFound(w, r)
		return
	}
	cfg := d.app.Snapshot()
	b, _ := json.Marshal(cfg)
	var current map[string]any
	_ = json.Unmarshal(b, &current)
	mode := r.FormValue("mode")
	denied := r.FormValue("denied_action")
	if (mode != "discard" && mode != "relay") || (denied != "reject" && denied != "discard") {
		http.Error(w, "Invalid policy", 400)
		return
	}
	current["mode"] = mode
	current["default_upstream"] = strings.TrimSpace(r.FormValue("default_upstream"))
	current["access"] = map[string]any{"allow_cidrs": textLines(r.FormValue("allow_cidrs")), "deny_cidrs": textLines(r.FormValue("deny_cidrs"))}
	current["targets"] = map[string]any{"allow": textLines(r.FormValue("target_allow")), "deny": textLines(r.FormValue("target_deny")), "denied_action": denied}
	var upstreams any
	var routes any
	if err := json.Unmarshal([]byte(r.FormValue("upstreams")), &upstreams); err != nil {
		d.render(w, r, token, "", "Upstreams must be a valid JSON array.")
		return
	}
	if _, ok := upstreams.([]any); !ok {
		d.render(w, r, token, "", "Upstreams must be a JSON array.")
		return
	}
	if err := json.Unmarshal([]byte(r.FormValue("routes")), &routes); err != nil {
		d.render(w, r, token, "", "Routes must be a valid JSON array.")
		return
	}
	if _, ok := routes.([]any); !ok {
		d.render(w, r, token, "", "Routes must be a JSON array.")
		return
	}
	// Strict typed decoding rejects fields such as raw passwords and OAuth tokens.
	current["upstreams"] = upstreams
	current["routes"] = routes
	b, _ = json.Marshal(current)
	decoder := json.NewDecoder(strings.NewReader(string(b)))
	decoder.DisallowUnknownFields()
	var next Config
	if err := decoder.Decode(&next); err != nil {
		d.render(w, r, token, "", "Invalid settings fields. Authentication values must use environment references.")
		return
	}
	if err := d.app.Update(next); err != nil {
		d.render(w, r, token, "", "Settings are invalid: "+err.Error())
		return
	}
	if err := d.store.ConfigChange(d.app.Snapshot(), remoteIP(r)); err != nil {
		_ = d.app.Update(cfg)
		http.Error(w, "Unable to persist settings; previous policy restored", 503)
		return
	}
	d.render(w, r, token, "Relay policy saved. New SMTP transactions use this policy; in-progress transactions retain their snapshot.", "")
}
func (d *dashboard) export(w http.ResponseWriter, r *http.Request) {
	rows := filteredEvents(d.store.Events(), r)
	if len(rows) > 10000 {
		rows = rows[:10000]
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"pabal-events.csv\"")
	io.WriteString(w, "\ufeff")
	out := csv.NewWriter(w)
	out.Write([]string{"id", "time", "kind", "client_ip", "sender", "recipients", "status", "upstream", "bytes", "summary"})
	for _, e := range rows {
		values := []string{e.ID, e.Time, e.Kind, e.ClientIP, e.Sender, strings.Join(e.Recipients, "; "), e.Status, e.Upstream, strconv.FormatInt(e.Bytes, 10), e.Summary}
		for i, v := range values {
			trim := strings.TrimSpace(v)
			if len(trim) > 0 && strings.ContainsRune("=+-@", rune(trim[0])) {
				values[i] = "'" + v
			}
		}
		out.Write(values)
	}
	out.Flush()
}
