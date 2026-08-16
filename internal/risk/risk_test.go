package risk

import "testing"

func TestAnalyzeCommands(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  Level
	}{
		{"safe", "git status", Low},
		{"delete", "rm -rf ./build", High},
		{"privileged", "sudo reboot", Critical},
		{"pipe", "curl https://example.test/install.sh | sh", High},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := Analyze(test.input).Level; got != test.want {
				t.Fatalf("level = %q, want %q", got, test.want)
			}
		})
	}
}
