package main

import (
	"bytes"
	"encoding/json"
	"errors"
	smtp "github.com/emersion/go-smtp"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfigAndAccess(t *testing.T) {
	c := DefaultConfig()
	if err := ValidateConfig(c); err != nil {
		t.Fatal(err)
	}
	c.Access.AllowCIDRs = []string{"203.0.113.0/24", "127.0.0.0/8"}
	c.Access.DenyCIDRs = []string{"203.0.113.8/32"}
	if !accessAllowed(c, netip.MustParseAddr("203.0.113.9")) || accessAllowed(c, netip.MustParseAddr("203.0.113.8")) || !accessAllowed(c, netip.MustParseAddr("::ffff:127.0.0.1")) {
		t.Fatal("allow/deny or mapped IPv4")
	}
	c.Access.AllowCIDRs = []string{"0.0.0.0/0"}
	if ValidateConfig(c) == nil {
		t.Fatal("catch-all accepted")
	}
	path := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(path, []byte(`{"upstreams":[{"name":"x","address":"localhost:587","username":"SECRET"}]}`), 0600)
	if _, err := LoadConfig(path); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("inline auth fields or secret leakage")
	}
	c = DefaultConfig()
	c.Upstreams = []Upstream{{Name: "mock", Address: "127.0.0.1:1025", TLS: "none", Auth: AuthConfig{Type: "none"}}}
	if ValidateConfig(c) != nil {
		t.Fatal("local plaintext denied")
	}
	c.Upstreams[0].Address = "localhost:1025"
	if ValidateConfig(c) == nil {
		t.Fatal("plaintext hostname accepted")
	}
	c.Upstreams[0].Address = "192.168.0.1:1025"
	if ValidateConfig(c) == nil {
		t.Fatal("plaintext nonloopback accepted")
	}
}
func TestDiscardNeverDialsAndNoContentRecorded(t *testing.T) {
	var events []Event
	a, err := NewApp(DefaultConfig(), func(e Event) { events = append(events, e) })
	if err != nil {
		t.Fatal(err)
	}
	a.deliver = func(Config, Upstream, string, []string, []byte) error { t.Fatal("discard dialed upstream"); return nil }
	s := relaySession{app: a, config: a.Snapshot(), clientIP: "127.0.0.1"}
	if err = s.Mail("", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Rcpt("recipient@example.test", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Data(strings.NewReader("From: sender@example.test\r\nSubject: SECRET SUBJECT\r\n\r\nSECRET BODY\r\n")); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), "SECRET") {
		t.Fatal("content recorded")
	}
	if len(events) != 2 || events[1].Status != "discarded" {
		t.Fatal("discard event")
	}
}
func routingConfig() Config {
	c := DefaultConfig()
	c.Mode = "relay"
	c.Upstreams = []Upstream{{Name: "one", Address: "127.0.0.1:1025", TLS: "none", Auth: AuthConfig{Type: "none"}}, {Name: "two", Address: "127.0.0.1:1026", TLS: "none", Auth: AuthConfig{Type: "none"}}}
	c.DefaultUpstream = "one"
	c.Routes = []Route{{Domain: "other.test", Upstream: "two"}}
	return c
}
func TestRecipientsRoutingAndFailure(t *testing.T) {
	c := routingConfig()
	c.Targets = TargetPolicy{Allow: []string{"@example.test", "@other.test"}, Deny: []string{"blocked@example.test"}, DeniedAction: "discard"}
	a, err := NewApp(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := relaySession{app: a, config: c, clientIP: "127.0.0.1"}
	s.Mail("sender@example.test", nil)
	if err = s.Rcpt("blocked@example.test", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Rcpt("valid@example.test", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Rcpt("different@other.test", nil); err == nil {
		t.Fatal("mixed upstream routes accepted")
	}
	calls := 0
	a.deliver = func(_ Config, u Upstream, from string, to []string, data []byte) error {
		calls++
		if u.Name != "one" || len(to) != 1 || to[0] != "valid@example.test" || from != "sender@example.test" || !bytes.HasSuffix(data, []byte("\r\n.raw\r\n")) {
			t.Fatal("forward routing/payload")
		}
		return nil
	}
	if err = s.Data(strings.NewReader("From: sender@example.test\r\n\r\n.raw\r\n")); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("forward count")
	}
	c.Targets.DeniedAction = "reject"
	a.Update(c)
	s.config = c
	s.Reset()
	s.Mail("", nil)
	if err = s.Rcpt("blocked@example.test", nil); err == nil {
		t.Fatal("deny precedence")
	}
	s.Rcpt("valid@example.test", nil)
	a.deliver = func(Config, Upstream, string, []string, []byte) error { return errors.New("PRIVATE AUTH FAILURE") }
	err = s.Data(strings.NewReader("From: sender@example.test\r\n\r\nbody\r\n"))
	if smtpErr, ok := err.(*smtp.SMTPError); !ok || smtpErr.Code != 451 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("sanitized temporary failure")
	}
}
func TestPolicySnapshotsAndValidation(t *testing.T) {
	c := DefaultConfig()
	a, _ := NewApp(c, nil)
	copy := a.Snapshot()
	copy.Access.AllowCIDRs[0] = "203.0.113.1/32"
	if a.Snapshot().Access.AllowCIDRs[0] != "127.0.0.1/32" {
		t.Fatal("snapshot alias")
	}
	bad := a.Snapshot()
	bad.Mode = "invalid"
	if a.Update(bad) == nil || a.Snapshot().Mode != "discard" {
		t.Fatal("non atomic invalid update")
	}
	changed := a.Snapshot()
	changed.Limits.MaxRecipients++
	if a.Update(changed) == nil {
		t.Fatal("live limit changed")
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				next := a.Snapshot()
				_ = a.Update(next)
			}
		}()
	}
	wg.Wait()
}
func TestSMTPProtocolAndDiscard(t *testing.T) {
	c := DefaultConfig()
	c.Limits.MaxMessageBytes = 1024
	c.Limits.MaxRecipients = 2
	c.Targets.Deny = []string{"denied@example.test"}
	var mu sync.Mutex
	var events []Event
	a, _ := NewApp(c, func(e Event) { mu.Lock(); defer mu.Unlock(); events = append(events, e) })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go a.ServeSMTP(listener)
	defer listener.Close()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	p := textproto.NewConn(conn)
	p.ReadResponse(220)
	command := func(line string, code int) string {
		t.Helper()
		if e := p.PrintfLine("%s", line); e != nil {
			t.Fatal(e)
		}
		_, text, e := p.ReadResponse(code)
		if e != nil {
			t.Fatalf("%s: %v", line, e)
		}
		return text
	}
	caps := command("EHLO local.test", 250)
	for _, cap := range []string{"8BITMIME", "PIPELINING", "SIZE 1024"} {
		if !strings.Contains(caps, cap) {
			t.Fatal("missing SMTP capability")
		}
	}
	command("MAIL FROM:<>", 250)
	command("RCPT TO:<denied@example.test>", 550)
	command("RCPT TO:<one@example.test>", 250)
	command("RCPT TO:<two@example.test>", 250)
	command("RCPT TO:<three@example.test>", 452)
	command("DATA", 354)
	w := p.DotWriter()
	w.Write([]byte("From: local@example.test\r\nSubject: PRIVATE\r\n\r\n.binary\xff\xfe\r\n"))
	w.Close()
	if _, _, e := p.ReadResponse(250); e != nil {
		t.Fatal(e)
	}
	command("QUIT", 221)
	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, event := range events {
		if event.Status == "discarded" {
			found = true
			if len(event.Recipients) != 2 {
				t.Fatal("recipient count")
			}
		}
	}
	if !found {
		t.Fatal("no discard event")
	}
}
func TestUpstreamTimeoutAndMissingEnv(t *testing.T) {
	t.Setenv("PABAL_TEST_USER", "")
	_, err := upstreamAuth(AuthConfig{Type: "plain", UsernameEnv: "PABAL_TEST_USER", PasswordEnv: "PABAL_TEST_PASS"}, "localhost")
	if err == nil {
		t.Fatal("missing env accepted")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(2 * time.Second))
		io.Copy(io.Discard, conn)
	}()
	c := DefaultConfig()
	c.Limits.TimeoutSeconds = 1
	u := Upstream{Name: "stall", Address: listener.Addr().String(), TLS: "none", Auth: AuthConfig{Type: "none"}}
	start := time.Now()
	if err = forward(c, u, "", []string{"one@example.test"}, nil); err == nil {
		t.Fatal("stalled upstream accepted")
	}
	if time.Since(start) > 1500*time.Millisecond {
		t.Fatal("deadline not enforced")
	}
	<-done
}

func TestPersistentSMTPConnectionPolicyRefresh(t *testing.T) {
	c := DefaultConfig()
	c.Limits.TimeoutSeconds = 3
	a, _ := NewApp(c, nil)
	var mu sync.Mutex
	calls := 0
	a.deliver = func(Config, Upstream, string, []string, []byte) error { mu.Lock(); calls++; mu.Unlock(); return nil }
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	go a.ServeSMTP(l)
	defer l.Close()
	conn, e := net.DialTimeout("tcp", l.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	p := textproto.NewConn(conn)
	p.ReadResponse(220)
	cmd := func(text string, code int) {
		t.Helper()
		p.PrintfLine("%s", text)
		if _, _, err := p.ReadResponse(code); err != nil {
			t.Fatal(err)
		}
	}
	data := func() {
		t.Helper()
		cmd("RCPT TO:<one@example.test>", 250)
		cmd("DATA", 354)
		w := p.DotWriter()
		w.Write([]byte("From: local@example.test\r\n\r\nmock\r\n"))
		w.Close()
		if _, _, err := p.ReadResponse(250); err != nil {
			t.Fatal(err)
		}
	}
	cmd("EHLO persistent.test", 250)
	cmd("MAIL FROM:<>", 250)
	next := routingConfig()
	next.Limits = c.Limits
	if e = a.Update(next); e != nil {
		t.Fatal(e)
	}
	data()
	mu.Lock()
	if calls != 0 {
		t.Fatal("in-progress transaction policy changed")
	}
	mu.Unlock()
	cmd("MAIL FROM:<>", 250)
	data()
	mu.Lock()
	if calls != 1 {
		t.Fatal("new transaction ignored mode update")
	}
	mu.Unlock()
	next = a.Snapshot()
	next.Access.DenyCIDRs = []string{"127.0.0.1/32"}
	if e = a.Update(next); e != nil {
		t.Fatal(e)
	}
	cmd("MAIL FROM:<>", 550)
}

func TestConnectionAndMessageResourceLimits(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	limited := &limitedListener{Listener: l, slots: make(chan struct{}, 1)}
	firstClient, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer firstClient.Close()
	firstServer, e := limited.Accept()
	if e != nil {
		t.Fatal(e)
	}
	secondClient, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer secondClient.Close()
	accepted := make(chan struct{})
	go func() { limited.Accept(); close(accepted) }()
	secondClient.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e = secondClient.Read(b[:]); e != io.EOF {
		t.Fatal("excess connection not closed")
	}
	firstServer.Close()
	firstServer.Close()
	l.Close()
	<-accepted
	c := DefaultConfig()
	c.Limits.MaxMessageBytes = 100
	a, _ := NewApp(c, nil)
	s := relaySession{app: a, clientIP: "127.0.0.1"}
	s.Mail("", nil)
	s.Rcpt("one@example.test", nil)
	e = s.Data(strings.NewReader(strings.Repeat("x", 101)))
	if status, ok := e.(*smtp.SMTPError); !ok || status.Code != 552 {
		t.Fatal("message byte limit")
	}
}
