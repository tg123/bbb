package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

func flagCompletionOutput(t *testing.T, app *cli.Command, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app.Writer = &stdout
	app.ErrWriter = &stderr
	args = append(append([]string{"bbb"}, args...), "--generate-shell-completion")
	originalArgs := os.Args
	os.Args = args
	t.Cleanup(func() { os.Args = originalArgs })
	if err := app.Run(context.Background(), args); err != nil {
		t.Fatalf("complete %q: %v\n%s", args, err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	return stdout.String()
}

func checkFlagCompletions(t *testing.T, output string, want, omit []string) {
	t.Helper()
	candidates := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		name, _, _ := strings.Cut(line, ":")
		if candidates[name] {
			t.Errorf("duplicate completion %q:\n%s", name, output)
		}
		candidates[name] = true
	}
	for _, name := range want {
		if !candidates[name] {
			t.Errorf("missing completion %q:\n%s", name, output)
		}
	}
	for _, name := range omit {
		if candidates[name] {
			t.Errorf("unexpected completion %q:\n%s", name, output)
		}
	}
}

func TestFlagAliasCompletion(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want []string
		omit []string
	}{
		{"long listing alias", []string{"ls", "--l"}, []string{"--long", "--loglevel"}, []string{"-l"}},
		{"relative alias", []string{"ll", "--rel"}, []string{"--relative"}, nil},
		{"quiet alias", []string{"cp", "--q"}, []string{"--quiet"}, []string{"-q"}},
		{"exclude alias", []string{"sync", "--ex"}, []string{"--exclude"}, []string{"-x"}},
		{"short aliases", []string{"du", "-"}, []string{"-s", "--summarize", "-h", "--help"}, nil},
		{"short primary names", []string{"sync", "-"}, []string{"-q", "--quiet", "-x", "--exclude"}, nil},
		{"long aliases only", []string{"sync", "--"}, []string{"--quiet", "--exclude"}, []string{"-q", "-x"}},
		{"tree command alias", []string{"lsr", "--l"}, []string{"--long", "--loglevel"}, nil},
		{"copy command alias", []string{"cpr", "--q"}, []string{"--quiet"}, nil},
		{"second copy command alias", []string{"cptree", "--q"}, []string{"--quiet"}, nil},
		{"remove command alias", []string{"rmr", "--q"}, []string{"--quiet"}, nil},
		{"nested azure flags", []string{"az", "mkcontainer", "-"}, []string{"--loglevel", "--help", "-h"}, []string{"--taskfile", "--state"}},
		{"nested s3 flags", []string{"s3", "mkbucket", "-"}, []string{"--loglevel", "--help", "-h"}, []string{"--taskfile", "--state"}},
		{"nested gs flags", []string{"gs", "mkbucket", "-"}, []string{"--loglevel", "--help", "-h"}, []string{"--taskfile", "--state"}},
		{"root hidden flags", []string{"--"}, []string{"--loglevel", "--help", "--version"}, []string{"--taskfile", "--state"}},
		{"local visible overrides", []string{"cp", "--"}, []string{"--taskfile", "--state"}, nil},
		{"completion command flags", []string{"completion", "-"}, []string{"--help", "-h"}, []string{"--loglevel", "--taskfile", "--state"}},
		{"completion shell flags", []string{"completion", "bash", "-"}, []string{"--help", "-h"}, []string{"--loglevel", "--taskfile", "--state"}},
		{"nested commands unchanged", []string{"az"}, []string{"mkcontainer"}, nil},
		{"after separator", []string{"sync", "--", "--ex"}, nil, []string{"--exclude"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			app := newApp()
			app.Before = nil
			checkFlagCompletions(t, flagCompletionOutput(t, app, test.args...), test.want, test.omit)
		})
	}
}

func TestFlagAliasCompletionDescriptions(t *testing.T) {
	app := newApp()
	app.Before = nil
	output := flagCompletionOutput(t, app, "sync", "--ex")
	if output != "--exclude:Exclude files matching this regex\n" {
		t.Fatalf("unexpected alias description: %q", output)
	}
}

func TestFlagAliasCompletionScope(t *testing.T) {
	for _, skipParsing := range []bool{false, true} {
		t.Run(fmt.Sprintf("skip parsing %t", skipParsing), func(t *testing.T) {
			app := &cli.Command{
				Name:                  "bbb",
				EnableShellCompletion: true,
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "g", Aliases: []string{"global"}},
					&cli.BoolFlag{Name: "r", Aliases: []string{"root-only"}, Local: true},
					&cli.BoolFlag{Name: "s", Aliases: []string{"secret"}, Hidden: true},
					&cli.BoolFlag{Name: "shadowed", Aliases: []string{"visible-ancestor"}},
				},
				Commands: []*cli.Command{{
					Name:    "group",
					Aliases: []string{"grp"},
					Flags: []cli.Flag{
						&cli.BoolFlag{Name: "m", Aliases: []string{"middle"}},
						&cli.BoolFlag{Name: "p", Aliases: []string{"parent-only"}, Local: true},
					},
					Commands: []*cli.Command{{
						Name:            "leaf",
						Aliases:         []string{"lf"},
						SkipFlagParsing: skipParsing,
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "l", Aliases: []string{"long"}},
							&cli.BoolFlag{Name: "hush", Aliases: []string{"hidden-alias"}, Hidden: true},
							&cli.BoolFlag{Name: "shadowed", Hidden: true},
						},
					}},
				}},
			}
			configureFlagCompletion(app)
			want := []string{"--long", "-l", "--help", "-h"}
			omit := []string{"-r", "--root-only", "-p", "--parent-only", "-s", "--secret", "--hush", "--hidden-alias", "--shadowed", "--visible-ancestor"}
			inherited := []string{"-g", "--global", "-m", "--middle"}
			if skipParsing {
				omit = append(omit, inherited...)
			} else {
				want = append(want, inherited...)
			}
			checkFlagCompletions(t, flagCompletionOutput(t, app, "grp", "lf", "-"), want, omit)
		})
	}
}

func TestFlagAliasCompletionPreservesCustomCallback(t *testing.T) {
	app := &cli.Command{
		Name:                  "bbb",
		EnableShellCompletion: true,
		ShellComplete: func(ctx context.Context, cmd *cli.Command) {
			fmt.Fprintln(cmd.Root().Writer, "custom")
		},
		Commands: []*cli.Command{{Name: "child"}},
	}
	configureFlagCompletion(app)
	if app.Commands[0].ShellComplete == nil {
		t.Fatal("child completion was not configured")
	}
	if output := flagCompletionOutput(t, app, "--"); output != "custom\n" {
		t.Fatalf("custom callback was replaced: %q", output)
	}
}
