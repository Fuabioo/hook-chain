package pathutil

import (
	"os"
	"strings"
)

// ExpandTilde replaces a leading ~/ with the user's home directory.
// Paths like ~user/... are left unchanged (only current user's ~ is expanded).
// If $HOME is not set, the path is returned as-is.
func ExpandTilde(path string) string {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path
	}
	home := os.Getenv("HOME")
	if home == "" {
		return path
	}
	return home + path[1:]
}
