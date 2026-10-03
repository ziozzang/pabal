package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockBackend struct {
	mu            sync.Mutex
	data          []byte
	from          string
	to            []string
	authenticated string
}

func (b *mockBackend) NewSession(*smtp.Conn) (smtp.Session, error) { return &mockSession{b: b}, nil }

type mockSession struct {
	b    *mockBackend
	from string
	to   []string
}

func (s *mockSession) AuthMechanisms() []string { return []string{"PLAIN", "LOGIN", "XOAUTH2"} }
func (s *mockSession) Auth(mech string) (sasl.Server, error) {
	mark := func() { s.b.mu.Lock(); s.b.authenticated = mech; s.b.mu.Unlock() }
	if mech == "PLAIN" {
		return sasl.NewPlainServer(func(identity, user, password string) error {
			if user != "mock-user" || password != "mock-password" {
				return errors.New("mock auth refused")
			}
			mark()
			return nil
		}), nil
	}
	return &mockSASL{mech: mech, mark: mark}, nil
}

type mockSASL struct {
	mech string
	step int
	mark func()
}

func (s *mockSASL) Next(response []byte) ([]byte, bool, error) {
	if s.mech == "XOAUTH2" {
		if string(response) != "user=mock-user\x01auth=Bearer mock-token\x01\x01" {
			return nil, false, errors.New("mock oauth refused")
		}
		s.mark()
		return nil, true, nil
	}
	s.step++
	switch s.step {
	case 1:
		return []byte("Username:"), false, nil
	case 2:
		if string(response) != "mock-user" {
			return nil, false, errors.New("mock user refused")
		}
		return []byte("Password:"), false, nil
	case 3:
		if string(response) != "mock-password" {
			return nil, false, errors.New("mock password refused")
		}
		s.mark()
		return nil, true, nil
	}
	return nil, false, errors.New("unexpected mock challenge")
}
func (s *mockSession) Mail(from string, _ *smtp.MailOptions) error { s.from = from; return nil }
func (s *mockSession) Rcpt(to string, _ *smtp.RcptOptions) error   { s.to = append(s.to, to); return nil }
func (s *mockSession) Data(r io.Reader) error {
	data, e := io.ReadAll(r)
	s.b.mu.Lock()
	defer s.b.mu.Unlock()
	s.b.data = data
	s.b.from = s.from
	s.b.to = append([]string{}, s.to...)
	return e
}
func (s *mockSession) Reset()        { s.from = ""; s.to = nil }
func (s *mockSession) Logout() error { return nil }
func mockCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	return cert, pool
}
func mockServer(t *testing.T, mode string) (*mockBackend, string, *tls.Config) {
	t.Helper()
	cert, pool := mockCertificate(t)
	backend := &mockBackend{}
	server := smtp.NewServer(backend)
	server.Domain = "localhost"
	server.ReadTimeout = 2 * time.Second
	server.WriteTimeout = 2 * time.Second
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if mode != "none" {
		server.TLSConfig = tlsConfig
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var serve net.Listener = listener
	if mode == "tls" {
		serve = tls.NewListener(listener, tlsConfig)
	}
	done := make(chan struct{})
	go func() { defer close(done); server.Serve(serve) }()
	t.Cleanup(func() { server.Close(); <-done })
	return backend, listener.Addr().String(), &tls.Config{ServerName: "localhost", RootCAs: pool, MinVersion: tls.VersionTLS12}
}
func TestUpstreamAuthenticationAndTLS(t *testing.T) {
	t.Setenv("PABAL_TEST_USERNAME", "mock-user")
	t.Setenv("PABAL_TEST_PASSWORD", "mock-password")
	t.Setenv("PABAL_TEST_TOKEN", "mock-token")
	for _, authType := range []string{"none", "plain", "login", "oauth2"} {
		for _, tlsMode := range []string{"starttls", "tls"} {
			t.Run(authType+"/"+tlsMode, func(t *testing.T) {
				backend, address, trusted := mockServer(t, tlsMode)
				auth := AuthConfig{Type: authType}
				if authType != "none" {
					auth.UsernameEnv = "PABAL_TEST_USERNAME"
				}
				if authType == "plain" || authType == "login" {
					auth.PasswordEnv = "PABAL_TEST_PASSWORD"
				}
				if authType == "oauth2" {
					auth.TokenEnv = "PABAL_TEST_TOKEN"
				}
				c := DefaultConfig()
				u := Upstream{Name: "mock", Address: address, TLS: tlsMode, Auth: auth}
				body := []byte("From: sender@example.test\r\nSubject: mock only\r\n\r\n.leading dot\r\nbytes:\xff\xfe\r\n")
				if e := forwardTLS(c, u, trusted, "sender@example.test", []string{"one@example.test", "two@example.test"}, body); e != nil {
					t.Fatal(e)
				}
				backend.mu.Lock()
				defer backend.mu.Unlock()
				if string(backend.data) != string(body) || len(backend.to) != 2 || backend.from != "sender@example.test" {
					t.Fatal("payload/envelope changed")
				}
				if authType != "none" && !strings.EqualFold(backend.authenticated, map[string]string{"plain": "PLAIN", "login": "LOGIN", "oauth2": "XOAUTH2"}[authType]) {
					t.Fatal("authentication skipped")
				}
			})
		}
	}
}
func TestUpstreamTLSVerificationAndPlainLocal(t *testing.T) {
	_, address, trusted := mockServer(t, "starttls")
	c := DefaultConfig()
	u := Upstream{Name: "mock", Address: address, TLS: "starttls", Auth: AuthConfig{Type: "none"}}
	if e := forward(c, u, "", []string{"one@example.test"}, []byte("From: sender@example.test\r\n\r\nbody\r\n")); e == nil {
		t.Fatal("untrusted cert accepted")
	}
	badName := trusted.Clone()
	badName.ServerName = "wrong.example.test"
	if e := forwardTLS(c, u, badName, "", []string{"one@example.test"}, nil); e == nil {
		t.Fatal("wrong hostname accepted")
	}
	backend, plainAddress, _ := mockServer(t, "none")
	u.Address = plainAddress
	if e := forward(c, u, "", []string{"one@example.test"}, nil); e == nil {
		t.Fatal("missing STARTTLS accepted")
	}
	u.TLS = "none"
	body := []byte("From: local@example.test\r\n\r\nlocal mock\r\n")
	if e := forward(c, u, "", []string{"one@example.test"}, body); e != nil {
		t.Fatal(e)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if string(backend.data) != string(body) {
		t.Fatal("local plaintext payload mismatch")
	}
}
