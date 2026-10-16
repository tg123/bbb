package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Shell regressions re-enter the test binary to exercise the real CLI backend.
func TestCompletionBackendProcess(t *testing.T) {
	if os.Getenv("BBB_COMPLETION_TEST_BACKEND") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			fmt.Print(runCompletionTest(t, os.Args[i+1:]...))
			os.Exit(0)
		}
	}
	t.Fatal("missing completion arguments")
}

func completionBackendEnv(t *testing.T, enabled bool) []string {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	value := "0"
	if enabled {
		value = "1"
	}
	return append(os.Environ(), "BBB_COMPLETION_TEST_BINARY="+binary, "BBB_COMPLETION_TEST_BACKEND="+value)
}

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
		{"empty after double dash", []string{"rm", "--", ""}},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := runCompletionTest(t, append(test.args, "--generate-shell-completion")...)
			if strings.Contains(test.name, "after double dash") && output != "" {
				t.Errorf("expected no completions after --, got %q", output)
			}
			content, err := os.ReadFile(file)
			if err != nil || string(content) != "keep" {
				t.Fatalf("completion modified file: content=%q, err=%v", content, err)
			}
		})
	}
}

func TestPowerShellCompletion(t *testing.T) {
	pwsh, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed")
	}
	script := runCompletionTest(t, "completion", "pwsh")
	for _, test := range []struct {
		name         string
		before       string
		after        string
		direct       bool
		backend      bool
		wantArgs     []string
		wantMatches  []string
		wantToolTips []string
	}{
		{
			name:        "command prefix",
			before:      "bbb c",
			wantArgs:    []string{"--generate-shell-completion"},
			wantMatches: []string{"cp", "cat"},
		},
		{
			name:         "flag prefix and description",
			before:       "bbb cp --con",
			wantArgs:     []string{"cp", "--con", "--generate-shell-completion"},
			wantMatches:  []string{"--concurrency"},
			wantToolTips: []string{"Concurrent requests: at once"},
		},
		{
			name:        "cursor before trailing words",
			before:      "bbb cp --con",
			after:       " ignored",
			wantArgs:    []string{"cp", "--con", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
		{
			name:        "cursor inside flag",
			before:      "bbb cp --con",
			after:       "currency ignored",
			wantArgs:    []string{"cp", "--con", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
		{
			name:        "cursor inside command",
			before:      "bbb c",
			after:       "p ignored",
			wantArgs:    []string{"--generate-shell-completion"},
			wantMatches: []string{"cp", "cat"},
		},
		{
			name:        "cursor before arguments",
			before:      "bbb ",
			after:       "rm protected.txt",
			wantArgs:    []string{"--generate-shell-completion"},
			wantMatches: []string{"cp", "cat", "mkcontainer", "pwsh", "--concurrency"},
		},
		{
			name:        "nested command",
			before:      "bbb az mk",
			wantArgs:    []string{"az", "--generate-shell-completion"},
			wantMatches: []string{"mkcontainer"},
		},
		{
			name:        "real backend separator prefix",
			before:      "bbb rm --",
			backend:     true,
			wantArgs:    []string{"rm", "--", "--generate-shell-completion"},
			wantMatches: []string{"--quiet", "--concurrency", "--retry-count", "--help", "--loglevel"},
		},
		{
			name:        "real backend empty after separator",
			before:      "bbb rm -- ",
			direct:      true,
			backend:     true,
			wantArgs:    []string{"rm", "--", "", "--generate-shell-completion"},
			wantMatches: []string{},
		},
		{
			name:        "real backend positional after separator",
			before:      "bbb rm -- pro",
			direct:      true,
			backend:     true,
			wantArgs:    []string{"rm", "--", "pro", "--generate-shell-completion"},
			wantMatches: []string{},
		},
		{
			name:        "real backend flag-like positional after separator",
			before:      "bbb rm -- --",
			direct:      true,
			backend:     true,
			wantArgs:    []string{"rm", "--", "--", "--generate-shell-completion"},
			wantMatches: []string{},
		},
		{
			name:        "real backend empty before trailing argument",
			before:      "bbb rm -- ",
			after:       "protected.txt",
			direct:      true,
			backend:     true,
			wantArgs:    []string{"rm", "--", "", "--generate-shell-completion"},
			wantMatches: []string{},
		},
		{
			name:         "candidate without description",
			before:       "bbb completion p",
			wantArgs:     []string{"completion", "--generate-shell-completion"},
			wantMatches:  []string{"pwsh"},
			wantToolTips: []string{"pwsh"},
		},
		{
			name:        "Windows executable name",
			before:      "bbb.exe c",
			wantArgs:    []string{"--generate-shell-completion"},
			wantMatches: []string{"cp", "cat"},
		},
		{
			name:        "redirection followed by space",
			before:      "bbb cat input > protected.txt ",
			direct:      true,
			wantArgs:    []string{"cat", "input", "--generate-shell-completion"},
			wantMatches: []string{"cp", "cat", "mkcontainer", "pwsh", "--concurrency"},
		},
		{
			name:        "redirection",
			before:      "bbb cat input > protected.txt --",
			wantArgs:    []string{"cat", "input", "--", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
		{
			name:        "error redirection",
			before:      "bbb cat input 2> protected.txt --",
			wantArgs:    []string{"cat", "input", "--", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
		{
			name:        "subexpression followed by space",
			before:      "bbb cat $(Set-Content protected.txt changed) ",
			wantArgs:    []string{"cat", "$(Set-Content protected.txt changed)", "--generate-shell-completion"},
			wantMatches: []string{"cp", "cat", "mkcontainer", "pwsh", "--concurrency"},
		},
		{
			name:        "subexpression",
			before:      "bbb cat $(Set-Content protected.txt changed) --",
			wantArgs:    []string{"cat", "$(Set-Content protected.txt changed)", "--", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
		{
			name:        "expandable string",
			before:      `bbb cat "a $HOME $(Set-Content protected.txt changed)" --`,
			wantArgs:    []string{"cat", "a $HOME $(Set-Content protected.txt changed)", "--", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
		{
			name:        "quoted flag value",
			before:      "bbb cp --taskfile='a b' --",
			wantArgs:    []string{"cp", "--taskfile=a b", "--", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
		{
			name:   "literal metacharacters",
			before: `bbb cat 'a b' 'single''quote' 'double"quote' '$HOME' ';' '|' '*' 'a\b' --`,
			wantArgs: []string{"cat", "a b", "single'quote", `double"quote`, "$HOME",
				";", "|", "*", `a\b`, "--", "--generate-shell-completion"},
			wantMatches: []string{"--concurrency"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			input, err := json.Marshal(map[string]any{"before": test.before, "after": test.after, "direct": test.direct})
			if err != nil {
				t.Fatal(err)
			}
			harness := `
$ErrorActionPreference = 'Stop'
function Register-ArgumentCompleter {
    param([switch]$Native, [string[]]$CommandName, [scriptblock]$ScriptBlock)
    $script:completionCallback = $ScriptBlock
    Microsoft.PowerShell.Core\Register-ArgumentCompleter @PSBoundParameters
}
function bbb {
    [System.IO.File]::WriteAllText((Join-Path $PWD 'request.json'), (ConvertTo-Json -InputObject @($args) -Compress))
    if ($env:BBB_COMPLETION_TEST_BACKEND -eq '1') {
        & $env:BBB_COMPLETION_TEST_BINARY '-test.run=^TestCompletionBackendProcess$' -- @args
        return
    }
    'cp:Copy files', 'cat:Print files', 'mkcontainer:Create containers', 'pwsh', '--concurrency:Concurrent requests: at once'
}
function bbb.exe { bbb @args }
. ./bbb.ps1
$case = Get-Content -Raw input.json | ConvertFrom-Json
$line = $case.before + $case.after
if ($case.direct) {
    # PowerShell can complete redirection targets itself instead of calling the callback.
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$null, [ref]$null)
    $commandAst = $ast.EndBlock.Statements[0].PipelineElements[0]
    $matches = @(& $script:completionCallback '' $commandAst $case.before.Length)
} else {
    $result = [System.Management.Automation.CommandCompletion]::CompleteInput($line, $case.before.Length, @{})
    $matches = @($result.CompletionMatches)
}
@{
    Matches = @($matches | ForEach-Object { $_.CompletionText })
    ToolTips = @($matches | ForEach-Object { $_.ToolTip })
} | ConvertTo-Json -Compress
`
			for name, content := range map[string]string{
				"bbb.ps1":       script,
				"input.json":    string(input),
				"harness.ps1":   harness,
				"protected.txt": "keep",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", "harness.ps1")
			cmd.Dir = dir
			cmd.Env = completionBackendEnv(t, test.backend)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("PowerShell completion: %v\n%s", err, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("unexpected stderr: %s", stderr.String())
			}
			request, err := os.ReadFile(filepath.Join(dir, "request.json"))
			if err != nil {
				t.Fatal(err)
			}
			var gotArgs []string
			if err := json.Unmarshal(request, &gotArgs); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(gotArgs, test.wantArgs) {
				t.Errorf("request arguments = %q, want %q", gotArgs, test.wantArgs)
			}
			var result struct {
				Matches  []string
				ToolTips []string
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode PowerShell output: %v\n%s", err, output)
			}
			if !reflect.DeepEqual(result.Matches, test.wantMatches) {
				t.Errorf("matches = %q, want %q", result.Matches, test.wantMatches)
			}
			if test.wantToolTips != nil && !reflect.DeepEqual(result.ToolTips, test.wantToolTips) {
				t.Errorf("tooltips = %q, want %q", result.ToolTips, test.wantToolTips)
			}
			content, err := os.ReadFile(filepath.Join(dir, "protected.txt"))
			if err != nil || string(content) != "keep" {
				t.Errorf("completion modified file: content=%q, err=%v", content, err)
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
				backend     bool
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
					name:        "real backend separator prefix",
					words:       []string{"bbb", "rm", "--"},
					cword:       2,
					backend:     true,
					wantArgs:    []string{"rm", "--", "--generate-shell-completion"},
					wantMatches: []string{"--quiet", "--concurrency", "--retry-count", "--help", "--loglevel"},
				},
				{
					name:        "real backend empty after separator",
					words:       []string{"bbb", "rm", "--", ""},
					cword:       3,
					backend:     true,
					wantArgs:    []string{"rm", "--", "", "--generate-shell-completion"},
					wantMatches: []string{},
				},
				{
					name:        "real backend positional after separator",
					words:       []string{"bbb", "rm", "--", "pro"},
					cword:       3,
					backend:     true,
					wantArgs:    []string{"rm", "--", "pro", "--generate-shell-completion"},
					wantMatches: []string{},
				},
				{
					name:        "real backend flag-like positional after separator",
					words:       []string{"bbb", "rm", "--", "--"},
					cword:       3,
					backend:     true,
					wantArgs:    []string{"rm", "--", "--", "--generate-shell-completion"},
					wantMatches: []string{},
				},
				{
					name:        "real backend empty before trailing argument",
					words:       []string{"bbb", "rm", "--", "", "protected.txt"},
					cword:       3,
					backend:     true,
					wantArgs:    []string{"rm", "--", "", "--generate-shell-completion"},
					wantMatches: []string{},
				},
				{
					name:        "real backend quoted command",
					words:       []string{"bbb", `"az"`, "mk"},
					cword:       2,
					backend:     true,
					wantArgs:    []string{"az", "--generate-shell-completion"},
					wantMatches: []string{"mkcontainer"},
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
					words: []string{"bbb", "cat", `'a b'`, `"single'quote"`, `'double"quote'`,
						"$(printf changed > protected.txt)", "`printf changed > protected.txt`",
						";", "|", "*", "$HOME", `'a\b'`, ""},
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
    if [[ $BBB_COMPLETION_TEST_BACKEND == 1 ]]; then
        "$BBB_COMPLETION_TEST_BINARY" '-test.run=^TestCompletionBackendProcess$' -- "$@"
        return
    fi
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
					cmd.Env = completionBackendEnv(t, test.backend)
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
						want := strings.Join(test.wantMatches, "\x00")
						if len(test.wantMatches) > 0 {
							want += "\x00"
						}
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
