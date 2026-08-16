package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriterRedactsSensitiveDataAndReadsSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "audit.jsonl")
	writer := New(path, true)
	err := writer.Write(Event{
		Timestamp: time.Now(),
		SessionID: "session-1",
		Event:     "policy_decision",
		Resource:  "GITHUB_TOKEN=super-secret",
		Details:   map[string]any{"OPENAI_API_KEY": "another-secret", "safe": "value"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret") || strings.Contains(string(raw), "another-secret") {
		t.Fatalf("audit leaked a secret: %s", raw)
	}
	events, err := Read(path, "session-1", 20)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%v err=%v", events, err)
	}
}

func TestDisabledWriterDoesNotCreateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := New(path, false).Write(Event{Event: "ignored"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file exists or unexpected error: %v", err)
	}
}
