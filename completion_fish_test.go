package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestFishCompletion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires native Fish")
	}
	fish, err := exec.LookPath("fish")
	if err != nil {
		t.Skip("fish is not installed")
	}
	script := runCompletionTest(t, "completion", "fish")
	for _, test := range []struct {
		name     string
		line     string
		wantArgs []string
		want     []string
		omit     []string
	}{
		{
			name:     "commands",
			line:     "bbb c",
			wantArgs: []string{"--generate-shell-completion"},
			want:     []string{"cp", "cat"},
		},
		{
			name:     "nested command",
			line:     "bbb az mk",
			wantArgs: []string{"az", "--generate-shell-completion"},
			want:     []string{"mkcontainer"},
		},
		{
			name:     "flags",
			line:     "bbb cp --con",
			wantArgs: []string{"cp", "--con", "--generate-shell-completion"},
			want:     []string{"--concurrency"},
		},
		{
			name:     "command and flag aliases",
			line:     "bbb cpr --q",
			wantArgs: []string{"cpr", "--q", "--generate-shell-completion"},
			want:     []string{"--quiet"},
		},
		{
			name:     "quoted current flag",
			line:     `bbb cpr "--q`,
			wantArgs: []string{"cpr", "--q", "--generate-shell-completion"},
			want:     []string{"--quiet"},
		},
		{
			name:     "local source",
			line:     "bbb cp ./some",
			wantArgs: []string{"cp", "--generate-shell-completion"},
			want:     []string{"./some-file.txt"},
		},
		{
			name:     "local destination",
			line:     "bbb cp ./some-file.txt ./some",
			wantArgs: []string{"cp", "./some-file.txt", "--generate-shell-completion"},
			want:     []string{"./some-file.txt"},
		},
		{
			name:     "local destination after remote source",
			line:     "bbb cp s3://completion-test/source ./some",
			wantArgs: []string{"cp", "s3://completion-test/source", "--generate-shell-completion"},
			want:     []string{"./some-file.txt"},
		},
		{
			name:     "local operand after separator",
			line:     "bbb rm -- ./some",
			wantArgs: []string{"rm", "--", "./some", "--generate-shell-completion"},
			want:     []string{"./some-file.txt"},
		},
		{
			name:     "empty operand after separator",
			line:     "bbb rm -- ",
			wantArgs: []string{"rm", "--", "", "--generate-shell-completion"},
			want:     []string{"some-file.txt"},
			omit:     []string{"--help", "--quiet", "--concurrency", "--loglevel"},
		},
		{
			name:     "quoted empty operand after separator",
			line:     `bbb rm -- ""`,
			wantArgs: []string{"rm", "--", "", "--generate-shell-completion"},
			want:     []string{"some-file.txt"},
			omit:     []string{"--help", "--quiet", "--concurrency", "--loglevel"},
		},
		{
			name:     "flag-like operand after separator",
			line:     "bbb rm -- --",
			wantArgs: []string{"rm", "--", "--", "--generate-shell-completion"},
			omit:     []string{"--help", "--quiet", "--concurrency", "--loglevel"},
		},
		{
			name:     "quoted separator",
			line:     `bbb rm "--" ./some`,
			wantArgs: []string{"rm", "--", "./some", "--generate-shell-completion"},
			want:     []string{"./some-file.txt"},
		},
		{
			name:     "quoted positional current prefix",
			line:     `bbb rm -- "./some`,
			wantArgs: []string{"rm", "--", "./some", "--generate-shell-completion"},
			want:     []string{"./some-file.txt"},
		},
		{
			name:     "literal current operand",
			line:     `bbb rm -- "$HOME; $(printf changed > some-file.txt)"`,
			wantArgs: []string{"rm", "--", "$HOME; $(printf changed > some-file.txt)", "--generate-shell-completion"},
			omit:     []string{"--help", "--quiet", "--concurrency", "--loglevel"},
		},
		{
			name:     "literal completed operands",
			line:     `bbb rm -- 'a b' '$HOME' '' ./some`,
			wantArgs: []string{"rm", "--", "a b", "$HOME", "", "./some", "--generate-shell-completion"},
			want:     []string{"./some-file.txt"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range map[string]string{
				"completion.fish": script,
				"some-file.txt":   "keep",
			} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			harness := `
function bbb
    printf '%s\0' $argv > request.args
    "$BBB_COMPLETION_TEST_BINARY" '-test.run=^TestCompletionBackendProcess$' -- $argv
end
source ./completion.fish
complete -C "$argv[1]"
`
			cmd := exec.Command(fish, "--no-config", "-c", harness, test.line)
			cmd.Dir = dir
			cmd.Env = completionBackendEnv(t, true)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			if err != nil || stderr.Len() != 0 {
				t.Fatalf("Fish completion: %v\n%s", err, stderr.String())
			}
			request, err := os.ReadFile(filepath.Join(dir, "request.args"))
			if err != nil {
				t.Fatal(err)
			}
			gotArgs := strings.Split(strings.TrimSuffix(string(request), "\x00"), "\x00")
			if !reflect.DeepEqual(gotArgs, test.wantArgs) {
				t.Errorf("request arguments = %q, want %q", gotArgs, test.wantArgs)
			}
			candidates := make(map[string]bool)
			for _, line := range strings.Split(string(output), "\n") {
				name, _, _ := strings.Cut(line, "\t")
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
			content, err := os.ReadFile(filepath.Join(dir, "some-file.txt"))
			if err != nil || string(content) != "keep" {
				t.Errorf("completion modified file: content=%q, err=%v", content, err)
			}
		})
	}
}
