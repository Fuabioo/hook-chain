package pathutil

import (
	"testing"
)

func TestExpandTilde(t *testing.T) {
	tests := []struct {
		name  string
		home  string
		input string
		want  string
	}{
		{"absolute path unchanged", "/home/alice", "/usr/bin/foo", "/usr/bin/foo"},
		{"relative path unchanged", "/home/alice", "foo", "foo"},
		{"tilde slash expands", "/home/alice", "~/bin/foo", "/home/alice/bin/foo"},
		{"bare tilde expands", "/home/alice", "~", "/home/alice"},
		{"tilde-user left alone", "/home/alice", "~bob/bin/foo", "~bob/bin/foo"},
		{"empty HOME no expansion", "", "~/bin/foo", "~/bin/foo"},
		{"empty string unchanged", "/home/alice", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", tt.home)
			got := ExpandTilde(tt.input)
			if got != tt.want {
				t.Errorf("ExpandTilde(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
