package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestZshCompletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires native Zsh")
	}
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed")
	}
	script := runCompletionTest(t, "completion", "zsh")
	for _, test := range []struct {
		name      string
		words     []string
		current   int
		prefix    string
		wantArgs  []string
		wantMatch string
		wantFiles bool
	}{
		{
			name:      "cursor before trailing arguments",
			words:     []string{"bbb", "cp", "--con", "src", "dst"},
			current:   3,
			prefix:    "--con",
			wantArgs:  []string{"cp", "--con", "--generate-shell-completion"},
			wantMatch: "--concurrency",
		},
		{
			name:      "cursor inside flag before trailing arguments",
			words:     []string{"bbb", "cp", "--concurrency", "src", "dst"},
			current:   3,
			prefix:    "--con",
			wantArgs:  []string{"cp", "--con", "--generate-shell-completion"},
			wantMatch: "--concurrency",
		},
		{
			name:      "cursor before command",
			words:     []string{"bbb", "", "rm", "protected.txt"},
			current:   2,
			wantArgs:  []string{"--generate-shell-completion"},
			wantMatch: "cp",
		},
		{
			name:      "quoted nested command",
			words:     []string{"bbb", `"az"`, "mk", "ignored"},
			current:   3,
			prefix:    "mk",
			wantArgs:  []string{"az", "--generate-shell-completion"},
			wantMatch: "mkcontainer",
		},
		{
			name:      "separator prefix",
			words:     []string{"bbb", "rm", "--"},
			current:   3,
			prefix:    "--",
			wantArgs:  []string{"rm", "--", "--generate-shell-completion"},
			wantMatch: "--help",
		},
		{
			name:      "empty after separator",
			words:     []string{"bbb", "rm", "--", "", "protected.txt"},
			current:   4,
			wantArgs:  []string{"rm", "--", "", "--generate-shell-completion"},
			wantFiles: true,
		},
		{
			name:      "flag-like positional after separator",
			words:     []string{"bbb", "rm", "--", "--"},
			current:   4,
			prefix:    "--",
			wantArgs:  []string{"rm", "--", "--", "--generate-shell-completion"},
			wantFiles: true,
		},
		{
			name:      "literal command substitution",
			words:     []string{"bbb", "cp", `--taskfile="$(printf changed > protected.txt)"`, "--con"},
			current:   4,
			prefix:    "--con",
			wantArgs:  []string{"cp", "--taskfile=$(printf changed > protected.txt)", "--con", "--generate-shell-completion"},
			wantMatch: "--concurrency",
		},
		{
			name:      "literal quoted metacharacters",
			words:     []string{"bbb", "cp", `--taskfile='$HOME;*|\'`, "--con"},
			current:   4,
			prefix:    "--con",
			wantArgs:  []string{"cp", `--taskfile=$HOME;*|\`, "--con", "--generate-shell-completion"},
			wantMatch: "--concurrency",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range map[string]string{
				"completion.zsh": script,
				"protected.txt":  "keep",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			harness := `
compdef() {}
_describe() { printf '%s\n' "${opts[@]}"; }
_files() { printf '%s\n' '__files__'; }
bbb() {
    printf '%s\0' "$@" > request.args
    "$BBB_COMPLETION_TEST_BINARY" '-test.run=^TestCompletionBackendProcess$' -- "$@"
}
source ./completion.zsh
CURRENT=$1
PREFIX=$2
shift 2
words=("$@")
_bbb
`
			args := []string{"-f", "-c", harness, "completion-test", fmt.Sprint(test.current), test.prefix}
			cmd := exec.Command(zsh, append(args, test.words...)...)
			cmd.Dir = dir
			cmd.Env = completionBackendEnv(t, true)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil || stderr.Len() != 0 {
				t.Fatalf("Zsh completion: %v\n%s", err, stderr.String())
			}
			request, err := os.ReadFile(filepath.Join(dir, "request.args"))
			if err != nil {
				t.Fatal(err)
			}
			gotArgs := strings.Split(strings.TrimSuffix(string(request), "\x00"), "\x00")
			if !reflect.DeepEqual(gotArgs, test.wantArgs) {
				t.Errorf("request arguments = %q, want %q", gotArgs, test.wantArgs)
			}
			if test.wantFiles {
				if string(output) != "__files__\n" {
					t.Errorf("expected filename fallback, got %q", output)
				}
			} else {
				found := false
				for _, line := range strings.Split(string(output), "\n") {
					name, _, _ := strings.Cut(line, ":")
					found = found || name == test.wantMatch
				}
				if !found {
					t.Errorf("missing candidate %q:\n%s", test.wantMatch, output)
				}
			}
			content, err := os.ReadFile(filepath.Join(dir, "protected.txt"))
			if err != nil || string(content) != "keep" {
				t.Errorf("completion modified file: content=%q, err=%v", content, err)
			}
		})
	}
}
