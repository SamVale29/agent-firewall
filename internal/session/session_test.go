package session

import "testing"

func TestNewSessionHasStablePolicyHashAndUniqueID(t *testing.T) {
	a, err := New([]string{"git", "status"}, "local", "monitor", map[string]string{"mode": "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]string{"git", "status"}, "local", "monitor", map[string]string{"mode": "monitor"})
	if err != nil {
		t.Fatal(err)
	}
	if a.ID == b.ID || a.PolicyHash != b.PolicyHash {
		t.Fatalf("id/hash invariant failed: a=%+v b=%+v", a, b)
	}
}
