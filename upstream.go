package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Auth secrets are resolved for each delivery, never included in Config/events.
func upstreamAuth(a AuthConfig, host string) (smtp.Auth, error) {
	if a.Type == "none" {
		return nil, nil
	}
	username := os.Getenv(a.UsernameEnv)
	if username == "" || strings.ContainsAny(username, "\r\n\x00\x01") {
		return nil, errors.New("authentication environment unavailable")
	}
	switch a.Type {
	case "plain", "login":
		password := os.Getenv(a.PasswordEnv)
		if password == "" {
			return nil, errors.New("authentication environment unavailable")
		}
		if a.Type == "plain" {
			return smtp.PlainAuth("", username, password, host), nil
		}
		return &loginAuth{username: username, password: password}, nil
	case "oauth2":
		token := os.Getenv(a.TokenEnv)
		if token == "" || strings.ContainsAny(token, "\r\n\x00\x01") {
			return nil, errors.New("authentication environment unavailable")
		}
		return &oauthAuth{username: username, token: token}, nil
	}
	return nil, errors.New("unknown authentication")
}

type loginAuth struct {
	username, password string
	step               int
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("TLS required for authentication")
	}
	a.step = 0
	return "LOGIN", nil, nil
}
func (a *loginAuth) Next(_ []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	}
	return nil, errors.New("unexpected authentication challenge")
}

type oauthAuth struct{ username, token string }

func (a *oauthAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if !server.TLS {
		return "", nil, errors.New("TLS required for authentication")
	}
	return "XOAUTH2", []byte("user=" + a.username + "\x01auth=Bearer " + a.token + "\x01\x01"), nil
}
func (a *oauthAuth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return nil, errors.New("OAuth authentication refused")
	}
	return nil, nil
}
func forward(c Config, u Upstream, from string, to []string, data []byte) error {
	return forwardTLS(c, u, nil, from, to, data)
}
func forwardTLS(c Config, u Upstream, testTLS *tls.Config, from string, to []string, data []byte) error {
	host, _, e := net.SplitHostPort(u.Address)
	if e != nil {
		return errors.New("invalid upstream address")
	}
	auth, e := upstreamAuth(u.Auth, host)
	if e != nil {
		return e
	}
	timeout := time.Duration(c.Limits.TimeoutSeconds) * time.Second
	conn, e := net.DialTimeout("tcp", u.Address, timeout)
	if e != nil {
		return e
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if testTLS != nil {
		tlsCfg = testTLS.Clone()
	}
	if u.TLS == "tls" {
		secure := tls.Client(conn, tlsCfg)
		if e = secure.Handshake(); e != nil {
			return e
		}
		conn = secure
	}
	client, e := smtp.NewClient(conn, host)
	if e != nil {
		return e
	}
	defer client.Close()
	if e = client.Hello(c.Domain); e != nil {
		return e
	}
	if u.TLS == "starttls" {
		if e = client.StartTLS(tlsCfg); e != nil {
			return e
		}
	}
	if auth != nil {
		if e = client.Auth(auth); e != nil {
			return e
		}
	}
	if bytes.IndexFunc(data, func(r rune) bool { return r > 127 }) >= 0 {
		if yes, _ := client.Extension("8BITMIME"); !yes {
			return errors.New("upstream lacks 8BITMIME")
		}
	}
	if e = client.Mail(from); e != nil {
		return e
	}
	for _, recipient := range to {
		if e = client.Rcpt(recipient); e != nil {
			return e
		}
	}
	writer, e := client.Data()
	if e != nil {
		return e
	}
	if _, e = writer.Write(data); e != nil {
		return e
	}
	if e = writer.Close(); e != nil {
		return e
	}
	_ = client.Quit()
	return nil
}
