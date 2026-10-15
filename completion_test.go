package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
