package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStorePersistenceCopiesAndFailureRollback(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	c := DefaultConfig()
	if err = s.SaveConfig(c); err != nil {
		t.Fatal(err)
	}
	ev := Event{ID: "one", Status: "discarded", Recipients: []string{"test@example.invalid"}}
	if err = s.RecordEvent(ev); err != nil {
		t.Fatal(err)
	}
	ev.Recipients[0] = "changed"
	rows := s.Events()
	rows[0].Recipients[0] = "other"
	if s.Events()[0].Recipients[0] != "test@example.invalid" {
		t.Fatal("snapshot aliases journal")
	}
	if err = s.SaveClient(ClientLabel{IP: "127.0.0.1", Name: "Local"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Events()) != 1 || again.Clients()["127.0.0.1"].Name != "Local" || again.Secret() != s.Secret() {
		t.Fatal("state did not persist")
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("state must be private")
	}
	previous := s.dir
	s.dir = filepath.Join(dir, "missing", "directory")
	newConfig := c
	newConfig.Mode = "relay"
	if err = s.ConfigChange(newConfig, "127.0.0.1"); err == nil {
		t.Fatal("expected persistence failure")
	}
	if s.SavedConfig().Mode != c.Mode || len(s.Changes()) != 1 {
		t.Fatal("failed change leaked into memory")
	}
	if err = s.SaveClient(ClientLabel{IP: "127.0.0.1", Name: "Wrong"}, "127.0.0.1"); err == nil {
		t.Fatal("expected failure")
	}
	if s.Clients()["127.0.0.1"].Name != "Local" || len(s.Changes()) != 1 {
		t.Fatal("failed label leaked into memory")
	}
	s.dir = previous
}
func TestStoreRotationAndBoundedReplay(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Repeat(" ", journalLimit)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.RecordEvent(Event{ID: "rotated", Status: "discarded"}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "events.jsonl.1")); err != nil {
		t.Fatal("journal was not rotated")
	}
	var content strings.Builder
	for n := 0; n < retainedEvents+2; n++ {
		content.WriteString("{\"id\":\"replay\",\"status\":\"accepted\"}\n")
	}
	if err = os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(content.String()), 0600); err != nil {
		t.Fatal(err)
	}
	again, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.Events()) != retainedEvents {
		t.Fatal("replay exceeded memory limit")
	}
}
