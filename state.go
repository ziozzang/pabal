package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const retainedEvents = 10000
const journalLimit = 5 * 1024 * 1024

type ClientLabel struct {
	IP        string `json:"ip"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	Note      string `json:"note"`
	UpdatedAt string `json:"updated_at"`
}
type Change struct {
	Time    string `json:"time"`
	ActorIP string `json:"actor_ip"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Before  string `json:"before"`
	After   string `json:"after"`
}
type savedState struct {
	Secret  string                 `json:"secret"`
	Config  *Config                `json:"config,omitempty"`
	Clients map[string]ClientLabel `json:"clients"`
	Changes []Change               `json:"changes"`
}
type Store struct {
	mu     sync.RWMutex
	dir    string
	state  savedState
	events []Event
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, state: savedState{Clients: map[string]ClientLabel{}}}
	path := filepath.Join(dir, "state.json")
	data, err := os.ReadFile(path)
	if err == nil {
		if err = json.Unmarshal(data, &s.state); err != nil {
			return nil, fmt.Errorf("invalid state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.state.Clients == nil {
		s.state.Clients = map[string]ClientLabel{}
	}
	if s.state.Secret == "" {
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return nil, err
		}
		s.state.Secret = hex.EncodeToString(key)
	}
	// Load oldest rotation first, retaining a bounded recent event window.
	for i := 4; i >= 0; i-- {
		name := "events.jsonl"
		if i > 0 {
			name = fmt.Sprintf("events.jsonl.%d", i)
		}
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			return nil, e
		}
		for _, line := range splitLines(b) {
			var ev Event
			if json.Unmarshal(line, &ev) == nil {
				s.events = append(s.events, ev)
				if len(s.events) > retainedEvents {
					s.events = s.events[len(s.events)-retainedEvents:]
				}
			}
		}
	}
	if err = s.persistLocked(); err != nil {
		return nil, err
	}
	return s, nil
}
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for n, c := range data {
		if c == '\n' {
			lines = append(lines, data[start:n])
			start = n + 1
		}
	}
	return lines
}
func (s *Store) persistLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(s.dir, "state.json")); err != nil {
		return err
	}
	directory, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func (s *Store) RecordEvent(ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	// Explicit event model never stores message content or SMTP authentication.
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	path := filepath.Join(s.dir, "events.jsonl")
	if info, e := os.Stat(path); e == nil && info.Size()+int64(len(b)) > journalLimit {
		_ = os.Remove(filepath.Join(s.dir, "events.jsonl.4"))
		for i := 3; i >= 1; i-- {
			old := filepath.Join(s.dir, fmt.Sprintf("events.jsonl.%d", i))
			if _, e = os.Stat(old); e == nil {
				if e = os.Rename(old, filepath.Join(s.dir, fmt.Sprintf("events.jsonl.%d", i+1))); e != nil {
					return e
				}
			}
		}
		if e = os.Rename(path, filepath.Join(s.dir, "events.jsonl.1")); e != nil {
			return e
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	ev.Recipients = append([]string(nil), ev.Recipients...)
	s.events = append(s.events, ev)
	if len(s.events) > retainedEvents {
		s.events = append([]Event(nil), s.events[len(s.events)-retainedEvents:]...)
	}
	return nil
}
func (s *Store) Events() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := append([]Event(nil), s.events...)
	for n := range rows {
		rows[n].Recipients = append([]string(nil), rows[n].Recipients...)
	}
	return rows
}
func (s *Store) Secret() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.state.Secret }
func (s *Store) SavedConfig() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.state.Config == nil {
		return nil
	}
	c := cloneConfig(*s.state.Config)
	return &c
}
func (s *Store) SaveConfig(c Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := s.state.Config
	v := cloneConfig(c)
	s.state.Config = &v
	if err := s.persistLocked(); err != nil {
		s.state.Config = previous
		return err
	}
	return nil
}
func (s *Store) Clients() map[string]ClientLabel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]ClientLabel{}
	for k, v := range s.state.Clients {
		out[k] = v
	}
	return out
}
func (s *Store) SaveClient(c ClientLabel, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state.Clients[c.IP]
	if old.Name == c.Name && old.Category == c.Category && old.Note == c.Note && old.IP == c.IP {
		return nil
	}
	before, _ := json.Marshal(old)
	after, _ := json.Marshal(c)
	previousChanges := append([]Change(nil), s.state.Changes...)
	_, existed := s.state.Clients[c.IP]
	s.state.Clients[c.IP] = c
	s.addChangeLocked(Change{Time: time.Now().UTC().Format(time.RFC3339), ActorIP: actor, Action: "client_label", Target: c.IP, Before: string(before), After: string(after)})
	if err := s.persistLocked(); err != nil {
		if existed {
			s.state.Clients[c.IP] = old
		} else {
			delete(s.state.Clients, c.IP)
		}
		s.state.Changes = previousChanges
		return err
	}
	return nil
}
func (s *Store) addChangeLocked(c Change) {
	s.state.Changes = append(s.state.Changes, c)
	if len(s.state.Changes) > 1000 {
		s.state.Changes = s.state.Changes[len(s.state.Changes)-1000:]
	}
}
func (s *Store) ConfigChange(c Config, actor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before := "{}"
	if s.state.Config != nil {
		b, _ := json.Marshal(s.state.Config)
		before = string(b)
	}
	after, _ := json.Marshal(c)
	if before == string(after) {
		return nil
	}
	previousConfig := s.state.Config
	previousChanges := append([]Change(nil), s.state.Changes...)
	v := cloneConfig(c)
	s.state.Config = &v
	s.addChangeLocked(Change{Time: time.Now().UTC().Format(time.RFC3339), ActorIP: actor, Action: "settings", Target: "relay_policy", Before: before, After: string(after)})
	if err := s.persistLocked(); err != nil {
		s.state.Config = previousConfig
		s.state.Changes = previousChanges
		return err
	}
	return nil
}
func (s *Store) Changes() []Change {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Change(nil), s.state.Changes...)
}
