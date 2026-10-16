package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func runCompletionTest(t *testing.T, args ...string) string {
	t.Helper()
	app := newApp()
	// Command completion does not need the process-wide logging and transport setup.
	app.Before = nil
	var stdout, stderr bytes.Buffer
	app.Writer = &stdout
	app.ErrWriter = &stderr

	args = append([]string{"bbb"}, args...)
	originalArgs := os.Args
	os.Args = args
	t.Cleanup(func() { os.Args = originalArgs })
	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("run %q: %v\n%s", args, err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr for %q: %s", args, stderr.String())
	}
	return stdout.String()
}

func TestCompletionScripts(t *testing.T) {
	for _, test := range []struct {
		shell string
		want  string
	}{
		{"bash", "complete -o bashdefault -o default -F __bbb_bash_autocomplete bbb"},
		{"zsh", "compdef _bbb bbb"},
		{"fish", "complete -c bbb -f -a '(__bbb_perform_completion)'"},
		{"pwsh", "Register-ArgumentCompleter -Native"},
	} {
		t.Run(test.shell, func(t *testing.T) {
			output := runCompletionTest(t, "completion", test.shell)
			if !strings.Contains(output, test.want) {
				t.Errorf("script missing %q:\n%s", test.want, output)
			}
			if !strings.Contains(output, "--generate-shell-completion") {
				t.Errorf("script missing completion callback:\n%s", output)
			}
		})
	}
}

func TestCompletionHelp(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		output := runCompletionTest(t, "--help")
		if !strings.Contains(output, "completion") {
			t.Fatalf("completion command missing from root help:\n%s", output)
		}
	})
	t.Run("shells", func(t *testing.T) {
		output := runCompletionTest(t, "completion", "--help")
		for _, shell := range []string{"bash", "zsh", "fish", "pwsh"} {
			if !strings.Contains(output, shell) {
				t.Errorf("shell %q missing from completion help:\n%s", shell, output)
			}
		}
	})
}

func TestCompletionCandidates(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want []string
		omit []string
	}{
		{"commands", nil, []string{"cp", "ls", "sync", "completion"}, nil},
		{"global flags", []string{"--"}, []string{"--loglevel", "--help", "--version"}, []string{"--taskfile", "--state"}},
		{"copy flags", []string{"cp", "--"}, []string{"--concurrency", "--retry-count", "--taskfile", "--state"}, nil},
		{"copy alias flags", []string{"cpr", "--"}, []string{"--concurrency", "--retry-count"}, nil},
		{"nested azure", []string{"az"}, []string{"mkcontainer"}, nil},
		{"nested s3", []string{"s3"}, []string{"mkbucket"}, nil},
		{"nested gs", []string{"gs"}, []string{"mkbucket"}, nil},
		{"shells", []string{"completion"}, []string{"bash", "zsh", "fish", "pwsh"}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := runCompletionTest(t, append(test.args, "--generate-shell-completion")...)
			candidates := make(map[string]bool)
			for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
				name, _, _ := strings.Cut(line, ":")
				candidates[name] = true
			}
			for _, want := range test.want {
				if !candidates[want] {
					t.Errorf("missing candidate %q:\n%s", want, output)
				}
			}
			for _, omit := range test.omit {
				if candidates[omit] {
					t.Errorf("unexpected candidate %q:\n%s", omit, output)
				}
			}
		})
	}
}

func TestCompletionDoesNotRunActions(t *testing.T) {
	file := filepath.Join(t.TempDir(), "keep.txt")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		args []string
	}{
		{"file argument", []string{"rm", file}},
		{"after double dash", []string{"rm", "--", file}},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := runCompletionTest(t, append(test.args, "--generate-shell-completion")...)
			if test.name == "after double dash" && output != "" {
				t.Errorf("expected no completions after --, got %q", output)
			}
			content, err := os.ReadFile(file)
			if err != nil || string(content) != "keep" {
				t.Fatalf("completion modified file: content=%q, err=%v", content, err)
			}
		})
	}
}

func TestBashCompletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires native Bash")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	script := runCompletionTest(t, "completion", "bash")
	for _, init := range []string{"legacy", "modern"} {
		t.Run(init, func(t *testing.T) {
			for _, test := range []struct {
				name        string
				words       []string
				cword       int
				list        bool
				wantArgs    []string
				wantMatches []string
			}{
				{
					name:        "command prefix",
					words:       []string{"bbb", "c"},
					cword:       1,
					wantArgs:    []string{"--generate-shell-completion"},
					wantMatches: []string{"cp", "cat"},
				},
				{
					name:        "flag prefix",
					words:       []string{"bbb", "cp", "--con"},
					cword:       2,
					wantArgs:    []string{"cp", "--con", "--generate-shell-completion"},
					wantMatches: []string{"--concurrency"},
				},
				{
					name:        "cursor before trailing words",
					words:       []string{"bbb", "cp", "--con", "ignored"},
					cword:       2,
					wantArgs:    []string{"cp", "--con", "--generate-shell-completion"},
					wantMatches: []string{"--concurrency"},
				},
				{
					name:        "descriptions",
					words:       []string{"bbb", "c"},
					cword:       1,
					list:        true,
					wantArgs:    []string{"--generate-shell-completion"},
					wantMatches: []string{"cp   -- Copy files", "cat  -- Print files"},
				},
				{
					name:     "redirection",
					words:    []string{"bbb", "cat", "input", ">", "protected.txt", ""},
					cword:    5,
					wantArgs: []string{"cat", "input", ">", "protected.txt", "--generate-shell-completion"},
				},
				{
					name:     "command substitutions",
					words:    []string{"bbb", "cat", "$(printf changed > protected.txt)", "`printf changed > protected.txt`", ""},
					cword:    4,
					wantArgs: []string{"cat", "$(printf changed > protected.txt)", "`printf changed > protected.txt`", "--generate-shell-completion"},
				},
				{
					name:     "command separator",
					words:    []string{"bbb", "cat", ";", "printf", "changed", ">", "protected.txt", "#", ""},
					cword:    8,
					wantArgs: []string{"cat", ";", "printf", "changed", ">", "protected.txt", "#", "--generate-shell-completion"},
				},
				{
					name: "literal metacharacters",
					words: []string{"bbb", "cat", "a b", "single'quote", `double"quote`,
						"$(printf changed > protected.txt)", "`printf changed > protected.txt`",
						";", "|", "*", "$HOME", `a\b`, ""},
					cword: 12,
					wantArgs: []string{"cat", "a b", "single'quote", `double"quote`,
						"$(printf changed > protected.txt)", "`printf changed > protected.txt`",
						";", "|", "*", "$HOME", `a\b`, "--generate-shell-completion"},
				},
			} {
				t.Run(test.name, func(t *testing.T) {
					dir := t.TempDir()
					for name, content := range map[string]string{
						"completion.bash": script,
						"protected.txt":   "keep",
					} {
						if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					harness := `
_get_comp_words_by_ref() {
    words=("${COMP_WORDS[@]}")
    cword=$COMP_CWORD
    cur=${words[cword]}
    prev=${words[cword-1]}
}
if [[ $1 == modern ]]; then
    _comp_initialize() { _get_comp_words_by_ref "$@"; }
fi
COMP_CWORD=$2
COMP_TYPE=$3
shift 3
COMP_WORDS=("$@")
bbb() {
    printf '%s\0' "$@" > request.args
    printf '%s\n' 'cp:Copy files' 'cat:Print files' '--concurrency:Concurrent requests'
}
source ./completion.bash
__bbb_bash_autocomplete || exit
if [[ ${#COMPREPLY[@]} -gt 0 ]]; then
    printf '%s\0' "${COMPREPLY[@]}"
fi
`
					compType := "9"
					if test.list {
						compType = "63"
					}
					args := []string{"--noprofile", "--norc", "-c", harness, "completion-test",
						init, fmt.Sprint(test.cword), compType}
					cmd := exec.Command(bash, append(args, test.words...)...)
					cmd.Dir = dir
					var stderr bytes.Buffer
					cmd.Stderr = &stderr
					output, err := cmd.Output()
					if err != nil {
						t.Fatalf("Bash completion: %v\n%s", err, stderr.String())
					}
					if stderr.Len() != 0 {
						t.Errorf("unexpected stderr: %s", stderr.String())
					}
					request, err := os.ReadFile(filepath.Join(dir, "request.args"))
					if err != nil {
						t.Fatal(err)
					}
					gotArgs := strings.Split(strings.TrimSuffix(string(request), "\x00"), "\x00")
					if !reflect.DeepEqual(gotArgs, test.wantArgs) {
						t.Errorf("request arguments = %q, want %q", gotArgs, test.wantArgs)
					}
					if test.wantMatches != nil {
						want := strings.Join(test.wantMatches, "\x00") + "\x00"
						if string(output) != want {
							t.Errorf("matches = %q, want %q", output, want)
						}
					}
					content, err := os.ReadFile(filepath.Join(dir, "protected.txt"))
					if err != nil || string(content) != "keep" {
						t.Errorf("completion modified file: content=%q, err=%v", content, err)
					}
				})
			}
		})
	}
}
