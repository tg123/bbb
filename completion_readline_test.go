package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty"
)

func TestZshLineEditorCompletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires native Zsh and a PTY")
	}
	zsh, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("zsh is not installed")
	}
	script := runCompletionTest(t, "completion", "zsh")
	for _, test := range []struct {
		name     string
		before   string
		after    string
		wantLine string
		wantArgs []string
	}{
		{
			name:     "flag before existing arguments",
			before:   "bbb cp --con",
			after:    " src dst",
			wantLine: "bbb cp --concurrency  src dst",
			wantArgs: []string{"cp", "--con", "--generate-shell-completion"},
		},
		{
			name:     "cursor inside flag",
			before:   "bbb cp --con",
			after:    "currency src dst",
			wantLine: "bbb cp --concurrency  src dst",
			wantArgs: []string{"cp", "--con", "--generate-shell-completion"},
		},
		{
			name:     "quoted nested command",
			before:   `bbb "az" mk`,
			after:    " ignored",
			wantLine: `bbb "az" mkcontainer  ignored`,
			wantArgs: []string{"az", "--generate-shell-completion"},
		},
		{
			name:     "empty after separator",
			before:   "bbb rm -- ",
			wantLine: "bbb rm -- protected.txt ",
			wantArgs: []string{"rm", "--", "", "--generate-shell-completion"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			work := filepath.Join(dir, "work")
			if err := os.Mkdir(work, 0o700); err != nil {
				t.Fatal(err)
			}
			harness := `
autoload -Uz compinit
compinit -D
source ../completion.zsh
bbb() {
    printf '%s\0' "$@" > ../request.args
    "$BBB_COMPLETION_TEST_BINARY" '-test.run=^TestCompletionBackendProcess$' -- "$@"
}
__bbb_capture_line() {
    printf '%s' "$BUFFER" > ../line
    BUFFER=exit
    CURSOR=4
}
zle -N __bbb_capture_line
bindkey -e
bindkey '^I' expand-or-complete
bindkey '^X^X' __bbb_capture_line
unsetopt BEEP
setopt COMPLETE_IN_WORD
PS1=
PS2=
RPS1=
`
			for name, content := range map[string]string{
				"completion.zsh":                       script,
				".zshrc":                               harness,
				filepath.Join("work", "protected.txt"): "keep",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, zsh, "-d", "-i")
			cmd.Dir = work
			cmd.Env = append(completionBackendEnv(t, true), "ZDOTDIR="+dir, "TERM=xterm")
			terminal, err := pty.Start(cmd)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := terminal.Close(); err != nil {
					t.Errorf("close PTY: %v", err)
				}
			})
			var output bytes.Buffer
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(&output, terminal)
				close(done)
			}()
			// Move back from the end of the existing arguments before pressing Tab.
			keys := test.before + test.after + strings.Repeat("\x02", len(test.after)) + "\t\x18\x18\n"
			_, writeErr := io.WriteString(terminal, keys)
			waitErr := cmd.Wait()
			<-done
			if writeErr != nil || waitErr != nil {
				t.Fatalf("Zsh line editor: write=%v, wait=%v\n%s", writeErr, waitErr, output.String())
			}
			line, err := os.ReadFile(filepath.Join(dir, "line"))
			if err != nil {
				t.Fatalf("read completed line: %v\n%s", err, output.String())
			}
			if string(line) != test.wantLine {
				t.Errorf("completed line = %q, want %q\n%s", line, test.wantLine, output.String())
			}
			request, err := os.ReadFile(filepath.Join(dir, "request.args"))
			if err != nil {
				t.Fatal(err)
			}
			gotArgs := strings.Split(strings.TrimSuffix(string(request), "\x00"), "\x00")
			if !reflect.DeepEqual(gotArgs, test.wantArgs) {
				t.Errorf("request arguments = %q, want %q", gotArgs, test.wantArgs)
			}
			content, err := os.ReadFile(filepath.Join(work, "protected.txt"))
			if err != nil || string(content) != "keep" {
				t.Errorf("completion modified file: content=%q, err=%v", content, err)
			}
		})
	}
}

func TestBashReadlineCompletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires native Bash and a PTY")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	var bashCompletion string
	for _, path := range []string{
		"/usr/share/bash-completion/bash_completion",
		"/etc/bash_completion",
		"/opt/homebrew/etc/profile.d/bash_completion.sh",
		"/usr/local/etc/profile.d/bash_completion.sh",
	} {
		if _, err := os.Stat(path); err == nil {
			bashCompletion = path
			break
		}
	}
	if bashCompletion == "" {
		t.Skip("bash-completion is not installed")
	}
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	t.Setenv("INPUTRC", "/dev/null")
	script := runCompletionTest(t, "completion", "bash")
	for _, test := range []struct {
		name     string
		line     string
		wantLine string
		wantArgs []string
	}{
		{
			name:     "double quoted command",
			line:     `bbb "az" mk`,
			wantLine: `bbb "az" mkcontainer `,
			wantArgs: []string{"az", "--generate-shell-completion"},
		},
		{
			name:     "single quoted command",
			line:     `bbb 'az' mk`,
			wantLine: `bbb 'az' mkcontainer `,
			wantArgs: []string{"az", "--generate-shell-completion"},
		},
		{
			name:     "escaped command",
			line:     `bbb a\z mk`,
			wantLine: `bbb a\z mkcontainer `,
			wantArgs: []string{"az", "--generate-shell-completion"},
		},
		{
			name:     "mixed quotes",
			line:     `bbb 'a'"z" mk`,
			wantLine: `bbb 'a'"z" mkcontainer `,
			wantArgs: []string{"az", "--generate-shell-completion"},
		},
		{
			name:     "escaped space",
			line:     `bbb cp --taskfile=a\ b --con`,
			wantLine: `bbb cp --taskfile=a\ b --concurrency `,
			wantArgs: []string{"cp", "--taskfile=a b", "--con", "--generate-shell-completion"},
		},
		{
			name:     "escaped double quotes and backslash",
			line:     `bbb cp --taskfile="a\"b\\c\q" --con`,
			wantLine: `bbb cp --taskfile="a\"b\\c\q" --concurrency `,
			wantArgs: []string{"cp", "--taskfile=a\"b\\c\\q", "--con", "--generate-shell-completion"},
		},
		{
			name:     "single quoted metacharacters",
			line:     `bbb cp --taskfile='$HOME;*|\' --con`,
			wantLine: `bbb cp --taskfile='$HOME;*|\' --concurrency `,
			wantArgs: []string{"cp", `--taskfile=$HOME;*|\`, "--con", "--generate-shell-completion"},
		},
		{
			name:     "command substitution is literal",
			line:     `bbb cp --taskfile="$(printf changed > protected.txt)" --con`,
			wantLine: `bbb cp --taskfile="$(printf changed > protected.txt)" --concurrency `,
			wantArgs: []string{"cp", "--taskfile=$(printf changed > protected.txt)", "--con", "--generate-shell-completion"},
		},
		{
			name:     "empty after separator allows filename fallback",
			line:     "bbb rm -- ",
			wantLine: "bbb rm -- protected.txt ",
			wantArgs: []string{"rm", "--", "", "--generate-shell-completion"},
		},
		{
			name:     "positional after separator allows filename fallback",
			line:     "bbb rm -- pro",
			wantLine: "bbb rm -- protected.txt ",
			wantArgs: []string{"rm", "--", "pro", "--generate-shell-completion"},
		},
		{
			name:     "flag-like positional after separator",
			line:     "bbb rm -- --",
			wantLine: "bbb rm -- --",
			wantArgs: []string{"rm", "--", "--", "--generate-shell-completion"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			// Only this file is visible to Bash's default filename completion.
			work := filepath.Join(dir, "work")
			if err := os.Mkdir(work, 0o700); err != nil {
				t.Fatal(err)
			}
			harness := `
source "$BBB_BASH_COMPLETION"
# Exercise the legacy path with actual COMP_WORDS supplied by Readline.
unset -f _comp_initialize
source ../completion.bash
bbb() {
    printf '%s\0' "$@" > ../request.args
    "$BBB_COMPLETION_TEST_BINARY" '-test.run=^TestCompletionBackendProcess$' -- "$@"
}
__bbb_capture_line() {
    printf '%s' "$READLINE_LINE" > ../line
    READLINE_LINE=exit
    READLINE_POINT=4
}
bind 'set enable-bracketed-paste off'
bind '"\t":complete'
bind -x '"\C-x\C-x":__bbb_capture_line'
PS1=
`
			for name, content := range map[string]string{
				"completion.bash":                      script,
				"harness.bash":                         harness,
				filepath.Join("work", "protected.txt"): "keep",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bash, "--noprofile", "--rcfile", "../harness.bash", "-i")
			cmd.Dir = work
			cmd.Env = append(completionBackendEnv(t, true), "BBB_BASH_COMPLETION="+bashCompletion, "TERM=dumb")
			terminal, err := pty.Start(cmd)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := terminal.Close(); err != nil {
					t.Errorf("close PTY: %v", err)
				}
			})
			var output bytes.Buffer
			done := make(chan struct{})
			go func() {
				_, _ = io.Copy(&output, terminal)
				close(done)
			}()
			// Tab invokes completion; the binding captures and replaces the line
			// before Enter so the user's command text is never executed.
			_, writeErr := io.WriteString(terminal, test.line+"\t\x18\x18\n")
			waitErr := cmd.Wait()
			<-done
			if writeErr != nil || waitErr != nil {
				t.Fatalf("Readline: write=%v, wait=%v\n%s", writeErr, waitErr, output.String())
			}
			line, err := os.ReadFile(filepath.Join(dir, "line"))
			if err != nil {
				t.Fatalf("read completed line: %v\n%s", err, output.String())
			}
			if string(line) != test.wantLine {
				t.Errorf("completed line = %q, want %q\n%s", line, test.wantLine, output.String())
			}
			request, err := os.ReadFile(filepath.Join(dir, "request.args"))
			if err != nil {
				t.Fatal(err)
			}
			gotArgs := strings.Split(strings.TrimSuffix(string(request), "\x00"), "\x00")
			if !reflect.DeepEqual(gotArgs, test.wantArgs) {
				t.Errorf("request arguments = %q, want %q", gotArgs, test.wantArgs)
			}
			content, err := os.ReadFile(filepath.Join(work, "protected.txt"))
			if err != nil || string(content) != "keep" {
				t.Errorf("completion modified file: content=%q, err=%v", content, err)
			}
		})
	}
}
