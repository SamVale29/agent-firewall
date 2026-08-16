// Package session models one firewall invocation without retaining secret values.
package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Record describes one firewall invocation and is safe to serialize in audit
// details without including environment values.
type Record struct {
	ID         string    `json:"session_id"`
	StartedAt  time.Time `json:"start_time"`
	EndedAt    time.Time `json:"end_time,omitempty"`
	Command    []string  `json:"command"`
	Backend    string    `json:"backend"`
	Mode       string    `json:"mode"`
	PolicyHash string    `json:"policy_hash"`
	ExitCode   int       `json:"exit_status,omitempty"`
}

// New creates a unique session identifier without an external dependency.
func New(command []string, backend, mode string, policyValue any) (Record, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return Record{}, fmt.Errorf("generate session id: %w", err)
	}
	id := "01" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes)
	hashInput, err := json.Marshal(policyValue)
	if err != nil {
		return Record{}, fmt.Errorf("hash policy: %w", err)
	}
	digest := sha256.Sum256(hashInput)
	return Record{
		ID:         id,
		StartedAt:  time.Now().UTC(),
		Command:    append([]string(nil), command...),
		Backend:    backend,
		Mode:       mode,
		PolicyHash: hex.EncodeToString(digest[:]),
	}, nil
}

// Finish records the child exit status and session end time.
func (r *Record) Finish(exitCode int) {
	r.ExitCode = exitCode
	r.EndedAt = time.Now().UTC()
}

// ShortID keeps terminal output compact while retaining enough entropy for a
// developer to correlate it with logs.
func (r Record) ShortID() string {
	if len(r.ID) <= 14 {
		return r.ID
	}
	return r.ID[:14]
}

func (r Record) String() string {
	return strings.Join(r.Command, " ")
}
