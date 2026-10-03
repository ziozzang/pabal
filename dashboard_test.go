package main

import (
	"encoding/csv"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func setupDashboard(t *testing.T) (http.Handler, *Store, *App) {
	t.Helper()
	s, e := NewStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	app, e := NewApp(DefaultConfig(), nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.SaveConfig(app.Snapshot()); e != nil {
		t.Fatal(e)
	}
	return NewDashboard(app, s), s, app
}
func dashboardGet(h http.Handler, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func dashboardPost(h http.Handler, path string, values url.Values, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func sessionValues(t *testing.T, h http.Handler) (*http.Cookie, string) {
	t.Helper()
	w := dashboardGet(h, "/")
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing session")
	}
	cookie := cookies[0]
	return cookie, strings.Split(cookie.Value, ".")[0]
}
func settingsValues(token string) url.Values {
	return url.Values{"csrf": {token}, "mode": {"discard"}, "denied_action": {"reject"}, "allow_cidrs": {"127.0.0.1/32\n::1/128"}, "deny_cidrs": {""}, "target_allow": {"@example.invalid"}, "target_deny": {"blocked@example.invalid"}, "default_upstream": {""}, "upstreams": {"[]"}, "routes": {"[]"}}
}
func TestDashboardRoutesFiltersEscapeAndCSV(t *testing.T) {
	h, s, _ := setupDashboard(t)
	s.RecordEvent(Event{ID: "first", Status: "discarded", Sender: "<script>sender</script>", Recipients: []string{"test@example.invalid"}, ClientIP: "127.0.0.1", Time: "2026-10-03T00:00:00Z"})
	s.RecordEvent(Event{ID: "second", Status: "rejected", Sender: "=FORMULA()", ClientIP: "127.0.0.2"})
	for _, path := range []string{"/", "/events", "/clients", "/settings", "/changes", "/events/first", "/readyz", "/livez", "/static/admin.css", "/static/admin.js"} {
		w := dashboardGet(h, path)
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
		if strings.Contains(w.Header().Get("Content-Type"), "text/html") && !strings.Contains(w.Body.String(), "</html>") {
			t.Fatalf("%s rendered incomplete page", path)
		}
	}
	body := dashboardGet(h, "/events?q=test@example.invalid&status=discarded&page=bad").Body.String()
	if !strings.Contains(body, "1 matching events") || strings.Contains(body, `href="/events/second"`) {
		t.Fatal("filters not applied")
	}
	if strings.Contains(body, "<script>sender") || !strings.Contains(body, "&lt;script&gt;sender") {
		t.Fatal("unescaped metadata")
	}
	w := dashboardGet(h, "/export/events.csv?status=rejected")
	reader := csv.NewReader(strings.NewReader(strings.TrimPrefix(w.Body.String(), "\ufeff")))
	records, e := reader.ReadAll()
	if e != nil || len(records) != 2 || records[1][4] != "'=FORMULA()" {
		t.Fatal("CSV filter or formula protection failed")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.20:1234"
	r.Header.Set("X-Forwarded-For", "127.0.0.1")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 403 {
		t.Fatal("external management request was allowed")
	}
	if dashboardGet(h, "/events/missing").Code != 404 {
		t.Fatal("missing event")
	}
}
func TestDashboardCSRFOriginSettingsAndClientAudit(t *testing.T) {
	h, s, app := setupDashboard(t)
	cookie, token := sessionValues(t, h)
	values := settingsValues(token)
	if dashboardPost(h, "/settings", values, nil, "").Code != 403 {
		t.Fatal("missing session accepted")
	}
	if dashboardPost(h, "/settings", values, cookie, "https://evil.invalid").Code != 403 {
		t.Fatal("cross-site origin accepted")
	}
	forged := *cookie
	forged.Value += "bad"
	if dashboardPost(h, "/settings", values, &forged, "").Code != 403 {
		t.Fatal("forged session accepted")
	}
	w := dashboardPost(h, "/settings", values, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Relay policy saved") {
		t.Fatal("default settings did not save")
	}
	if len(app.Snapshot().Targets.Allow) != 1 {
		t.Fatal("policy was not updated")
	}
	values.Set("upstreams", `[{"name":"x","address":"127.0.0.1:1025","tls":"none","auth":{"type":"plain","password":"secret"}}]`)
	w = dashboardPost(h, "/settings", values, cookie, "")
	if strings.Contains(w.Body.String(), "secret") || !strings.Contains(w.Body.String(), "environment references") {
		t.Fatal("raw credential accepted or exposed")
	}
	client := url.Values{"csrf": {token}, "ip": {"127.0.0.2"}, "name": {"<script>app</script>"}, "category": {"Testing"}, "note": {"check delivery"}}
	w = dashboardPost(h, "/clients", client, cookie, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "metadata saved") {
		t.Fatal("client label not saved")
	}
	if len(s.Changes()) != 2 {
		t.Fatal("audit not recorded")
	}
	if s.Changes()[1].ActorIP != "127.0.0.1" {
		t.Fatal("incorrect actor")
	}
	if dashboardPost(h, "/clients", client, cookie, "").Code != 200 || len(s.Changes()) != 2 {
		t.Fatal("no-op save produced audit")
	}
	body := dashboardGet(h, "/clients?q=app&category=Testing").Body.String()
	if !strings.Contains(body, "&lt;script&gt;app") {
		t.Fatal("registry escaping failed")
	}
	values = settingsValues(token)
	values.Set("allow_cidrs", "invalid CIDR")
	w = dashboardPost(h, "/settings", values, cookie, "")
	if !strings.Contains(w.Body.String(), "Settings are invalid") {
		t.Fatal("invalid policy accepted")
	}
	r := httptest.NewRequest("POST", "/clients", io.NopCloser(strings.NewReader(client.Encode())))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.AddCookie(cookie)
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 403 {
		t.Fatal("fetch-site cross-site accepted")
	}
}

func TestDashboardClientBlockUnblockAndPersistenceRollback(t *testing.T) {
	h, s, app := setupDashboard(t)
	cookie, token := sessionValues(t, h)
	values := url.Values{"csrf": {token}, "ip": {"127.0.0.2"}, "action": {"block"}}
	if w := dashboardPost(h, "/clients/policy", values, cookie, ""); w.Code != 303 {
		t.Fatal("client block failed")
	}
	if len(app.Snapshot().Access.DenyCIDRs) != 1 || app.Snapshot().Access.DenyCIDRs[0] != "127.0.0.2/32" {
		t.Fatal("exact deny not applied")
	}
	if len(s.Changes()) != 1 {
		t.Fatal("policy change not audited")
	}
	values.Set("action", "unblock")
	if w := dashboardPost(h, "/clients/policy", values, cookie, ""); w.Code != 303 {
		t.Fatal("client unblock failed")
	}
	if len(app.Snapshot().Access.DenyCIDRs) != 0 {
		t.Fatal("exact deny was not removed")
	}
	// Broad network rules remain untouched by the singleton unblock action.
	c := app.Snapshot()
	c.Access.DenyCIDRs = []string{"127.0.0.0/24"}
	if err := app.Update(c); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	if w := dashboardPost(h, "/clients/policy", values, cookie, ""); w.Code != 303 {
		t.Fatal("unblock request failed")
	}
	if len(app.Snapshot().Access.DenyCIDRs) != 1 {
		t.Fatal("broad deny rule was removed")
	}
	before := s.SavedConfig()
	auditCount := len(s.Changes())
	s.dir = s.dir + "/missing/path"
	values.Set("action", "block")
	if w := dashboardPost(h, "/clients/policy", values, cookie, ""); w.Code != 503 {
		t.Fatal("write failure not reported")
	}
	if len(app.Snapshot().Access.DenyCIDRs) != len(before.Access.DenyCIDRs) || len(s.Changes()) != auditCount {
		t.Fatal("failed mutation survived rollback")
	}
}
