package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsSensitiveAssignments(t *testing.T) {
	input := "GITHUB_TOKEN=abc123 password: hunter2 normal=value"
	output := Text(input)
	if strings.Contains(output, "abc123") || strings.Contains(output, "hunter2") {
		t.Fatalf("secret leaked in %q", output)
	}
	if !strings.Contains(output, "normal=value") {
		t.Fatalf("non-secret assignment unexpectedly changed: %q", output)
	}
}

func TestValueRedactsSensitiveEnvironment(t *testing.T) {
	if got := Value("OPENAI_API_KEY", "secret"); got != "[REDACTED]" {
		t.Fatalf("got %q", got)
	}
}
