package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	smtp "github.com/emersion/go-smtp"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Event struct {
	ID         string   `json:"id"`
	Time       string   `json:"time"`
	Kind       string   `json:"kind"`
	ClientIP   string   `json:"client_ip"`
	Sender     string   `json:"sender"`
	Recipients []string `json:"recipients"`
	Status     string   `json:"status"`
	Upstream   string   `json:"upstream,omitempty"`
	Bytes      int64    `json:"bytes"`
	Summary    string   `json:"summary"`
}
type App struct {
	mu      sync.RWMutex
	config  Config
	record  func(Event)
	deliver func(Config, Upstream, string, []string, []byte) error
}

func NewApp(c Config, record func(Event)) (*App, error) {
	c = normalizeConfig(cloneConfig(c))
	if e := ValidateConfig(c); e != nil {
		return nil, e
	}
	if record == nil {
		record = func(Event) {}
	}
	return &App{config: cloneConfig(c), record: record, deliver: forward}, nil
}
func (a *App) Snapshot() Config { a.mu.RLock(); defer a.mu.RUnlock(); return cloneConfig(a.config) }
func (a *App) Update(c Config) error {
	c = normalizeConfig(cloneConfig(c))
	if e := ValidateConfig(c); e != nil {
		return e
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c.SMTPListen != a.config.SMTPListen || c.AdminListen != a.config.AdminListen || c.Domain != a.config.Domain || !reflect.DeepEqual(c.Limits, a.config.Limits) {
		return errors.New("listeners, domain and resource limits require restart")
	}
	a.config = cloneConfig(c)
	return nil
}
func (a *App) emit(e Event) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		e.ID = hex.EncodeToString(b)
	} else {
		e.ID = time.Now().UTC().Format("20060102T150405.000000000")
	}
	e.Time = time.Now().UTC().Format(time.RFC3339Nano)
	e.Recipients = append([]string{}, e.Recipients...)
	a.record(e)
}
func (a *App) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	c := a.Snapshot()
	remote, ok := conn.Conn().RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, &smtp.SMTPError{Code: 550, Message: "Access denied"}
	}
	ip, ok := netip.AddrFromSlice(remote.IP)
	if !ok || !accessAllowed(c, ip) {
		a.emit(Event{Kind: "rejection", Status: "rejected", ClientIP: ip.Unmap().String(), Summary: "Client IP denied"})
		return nil, &smtp.SMTPError{Code: 550, Message: "Access denied"}
	}
	return &relaySession{app: a, config: c, clientIP: ip.Unmap().String()}, nil
}

type relaySession struct {
	app                          *App
	config                       Config
	clientIP, from               string
	accepted, dropped, forwarded []string
	upstream                     Upstream
}

func (s *relaySession) reject(summary string, recipient string) error {
	to := []string{}
	if recipient != "" {
		to = append(to, recipient)
	}
	s.app.emit(Event{Kind: "rejection", Status: "rejected", ClientIP: s.clientIP, Sender: s.from, Recipients: to, Summary: summary})
	return &smtp.SMTPError{Code: 550, Message: summary}
}
func (s *relaySession) Mail(from string, _ *smtp.MailOptions) error {
	s.Reset()
	s.config = s.app.Snapshot()
	ip, parseErr := netip.ParseAddr(s.clientIP)
	if parseErr != nil || !accessAllowed(s.config, ip) {
		return s.reject("Client IP denied", "")
	}
	if from != "" && !validMailbox(from) {
		return s.reject("Invalid envelope sender", "")
	}
	s.from = from
	if len(s.config.AllowedSenders) > 0 {
		allowed := false
		for _, p := range s.config.AllowedSenders {
			if patternMatches(p, from) {
				allowed = true
				break
			}
		}
		if !allowed {
			return s.reject("Sender not permitted", "")
		}
	}
	s.from = from
	s.app.emit(Event{Kind: "arrival", Status: "accepted", ClientIP: s.clientIP, Sender: from, Summary: "Envelope accepted; message DATA not yet received"})
	return nil
}
func (s *relaySession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if !validMailbox(to) {
		return s.reject("Invalid recipient", "")
	}
	if len(s.accepted) >= s.config.Limits.MaxRecipients {
		return &smtp.SMTPError{Code: 452, Message: "Recipient limit reached"}
	}
	dropped := !recipientAllowed(s.config, to)
	if dropped && s.config.Targets.DeniedAction == "reject" {
		return s.reject("Recipient denied", to)
	}
	var upstream Upstream
	if !dropped && s.config.Mode == "relay" {
		var ok bool
		upstream, ok = selectUpstream(s.config, to)
		if !ok {
			return s.reject("No upstream route for recipient", to)
		}
		if s.upstream.Name != "" && s.upstream.Name != upstream.Name {
			return s.reject("Mixed upstream routes require separate SMTP transactions", to)
		}
	}
	s.accepted = append(s.accepted, to)
	if dropped || s.config.Mode == "discard" {
		s.dropped = append(s.dropped, to)
	} else {
		s.upstream = upstream
		s.forwarded = append(s.forwarded, to)
	}
	return nil
}
func (s *relaySession) Data(reader io.Reader) error {
	data, e := io.ReadAll(io.LimitReader(reader, s.config.Limits.MaxMessageBytes+1))
	if e != nil {
		return &smtp.SMTPError{Code: 451, Message: "Message read failed"}
	}
	if int64(len(data)) > s.config.Limits.MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, Message: "Message size exceeded"}
	}
	if len(s.accepted) == 0 {
		return &smtp.SMTPError{Code: 554, Message: "No recipients"}
	}
	parsed, e := mail.ReadMessage(strings.NewReader(string(data)))
	if e != nil {
		return &smtp.SMTPError{Code: 554, Message: "Invalid message headers"}
	}
	if len(parsed.Header["Received"]) >= 100 {
		return &smtp.SMTPError{Code: 554, Message: "Relay hop limit exceeded"}
	}
	if len(s.forwarded) > 0 {
		trace := "Received: by " + s.config.Domain + " with ESMTP; " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n"
		if e = s.app.deliver(s.config, s.upstream, s.from, s.forwarded, append([]byte(trace), data...)); e != nil {
			s.app.emit(Event{Kind: "error", Status: "temporary_failure", ClientIP: s.clientIP, Sender: s.from, Recipients: s.accepted, Upstream: s.upstream.Name, Bytes: int64(len(data)), Summary: "Upstream unavailable; submitting client must retry"})
			return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Upstream unavailable; retry required"}
		}
		s.app.emit(Event{Kind: "delivery", Status: "relayed", ClientIP: s.clientIP, Sender: s.from, Recipients: s.forwarded, Upstream: s.upstream.Name, Bytes: int64(len(data)), Summary: "Upstream acknowledged message"})
	}
	if len(s.dropped) > 0 {
		s.app.emit(Event{Kind: "discard", Status: "discarded", ClientIP: s.clientIP, Sender: s.from, Recipients: s.dropped, Bytes: int64(len(data)), Summary: "Message discarded by policy; no content retained"})
	}
	return nil
}
func (s *relaySession) Reset() {
	s.from = ""
	s.accepted = nil
	s.dropped = nil
	s.forwarded = nil
	s.upstream = Upstream{}
}
func (s *relaySession) Logout() error { return nil }

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}
func (a *App) ServeSMTP(listener net.Listener) error {
	c := a.Snapshot()
	server := smtp.NewServer(a)
	server.Domain = c.Domain
	server.MaxMessageBytes = c.Limits.MaxMessageBytes
	server.MaxRecipients = c.Limits.MaxRecipients
	server.ReadTimeout = time.Duration(c.Limits.TimeoutSeconds) * time.Second
	server.WriteTimeout = server.ReadTimeout
	return server.Serve(&limitedListener{Listener: listener, slots: make(chan struct{}, c.Limits.MaxConnections)})
}
