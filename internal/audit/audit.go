package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/SamVale29/agent-firewall/internal/redact"
)

// Event is a JSONL-compatible audit record. Extra fields are intentionally
// represented by Details so the schema can grow without leaking ad-hoc maps.
type Event struct {
	Timestamp    time.Time      `json:"timestamp"`
	SessionID    string         `json:"session_id"`
	Event        string         `json:"event"`
	ResourceType string         `json:"resource_type,omitempty"`
	Resource     string         `json:"resource,omitempty"`
	Decision     string         `json:"decision,omitempty"`
	Risk         string         `json:"risk,omitempty"`
	Rule         string         `json:"rule,omitempty"`
	Reason       string         `json:"reason,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

// Writer appends redacted audit events to a local file.
type Writer struct {
	path    string
	enabled bool
	mu      sync.Mutex
}

// New creates an audit writer. The file is created lazily on the first event.
func New(path string, enabled bool) *Writer { return &Writer{path: path, enabled: enabled} }

func (w *Writer) Path() string { return w.path }

// Write appends one event atomically with respect to this process.
func (w *Writer) Write(event Event) error {
	if !w.enabled {
		return nil
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Timestamp = event.Timestamp.UTC()
	event.Resource = redact.Text(event.Resource)
	event.Reason = redact.Text(event.Reason)
	event.Rule = redact.Text(event.Rule)
	if event.Details != nil {
		event.Details = redactDetails(event.Details)
	}
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode audit event: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(w.path), 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write audit log: %w", err)
	}
	return nil
}

func redactDetails(details map[string]any) map[string]any {
	result := make(map[string]any, len(details))
	for key, value := range details {
		if redact.NameLooksSensitive(key) {
			result[key] = "[REDACTED]"
			continue
		}
		switch typed := value.(type) {
		case string:
			result[key] = redact.Text(typed)
		default:
			result[key] = typed
		}
	}
	return result
}

// Read returns the newest matching events from the JSONL file.
func Read(path, session string, last int) ([]Event, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return []Event{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var events []Event
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("parse audit line: %w", err)
		}
		if session == "" || event.SessionID == session {
			events = append(events, event)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if last > 0 && len(events) > last {
		events = events[len(events)-last:]
	}
	return events, nil
}

// Summary counts common session decisions for shareable output.
func Summary(events []Event) map[string]int {
	result := map[string]int{"allowed": 0, "prompted": 0, "blocked": 0}
	for _, event := range events {
		switch event.Decision {
		case "allow":
			result["allowed"]++
		case "ask":
			result["prompted"]++
		case "deny":
			result["blocked"]++
		}
	}
	return result
}

// StableNumbers is useful for deterministic doctor/status output.
func StableNumbers(values []int) []int {
	result := append([]int(nil), values...)
	sort.Ints(result)
	return result
}

func FormatCount(value int) string { return strconv.Itoa(value) }
