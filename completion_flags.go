package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"unicode/utf8"

	"github.com/urfave/cli/v3"
)

func configureFlagCompletion(cmd *cli.Command) {
	if cmd.ShellComplete == nil {
		cmd.ShellComplete = completeWithFlagAliases
	}
	for _, child := range cmd.Commands {
		configureFlagCompletion(child)
	}
}

func completeWithFlagAliases(ctx context.Context, cmd *cli.Command) {
	// Use the original token: parsing can consume prefixes such as --l as -l.
	args := os.Args
	if len(args) > 0 && args[len(args)-1] == "--generate-shell-completion" {
		args = args[:len(args)-1]
	}
	if len(args) == 0 || !strings.HasPrefix(args[len(args)-1], "-") {
		cli.DefaultCompleteWithFlags(ctx, cmd)
		return
	}
	lastArg := args[len(args)-1]
	prefix := strings.TrimLeft(lastArg, "-")
	flags := cmd.VisibleFlags()
	if !cmd.SkipFlagParsing {
		flags = append(flags, cmd.VisiblePersistentFlags()...)
	}
	seen := make(map[string]bool)
	for _, flag := range flags {
		usage := ""
		if documented, ok := flag.(cli.DocGenerationFlag); ok {
			usage = documented.GetUsage()
		}
		for _, name := range flag.Names() {
			name = strings.TrimSpace(name)
			if name == "" || !strings.HasPrefix(name, prefix) || name == prefix {
				continue
			}
			dashes := "--"
			if utf8.RuneCountInString(name) == 1 {
				if strings.HasPrefix(lastArg, "--") {
					continue
				}
				dashes = "-"
			}
			candidate := dashes + name
			if seen[candidate] {
				continue
			}
			seen[candidate] = true
			if usage != "" {
				candidate += ":" + usage
			}
			if _, err := fmt.Fprintln(cmd.Root().Writer, candidate); err != nil {
				slog.ErrorContext(ctx, "write flag completion", "err", err)
				return
			}
		}
	}
}
