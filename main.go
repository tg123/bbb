package main

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"log/slog"

	"github.com/urfave/cli/v3"

	"github.com/tg123/bbb/internal/azblob"
	"github.com/tg123/bbb/internal/bbbfs"
	"github.com/tg123/bbb/internal/fsops"
	"github.com/tg123/bbb/internal/hf"
)

var mainver string = "(devel)"

const hfScheme = bbbfs.HFScheme

func version() string {
	v := mainver

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}

	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			v = fmt.Sprintf("%v, %v", v, s.Value[:9])
		case "vcs.time":
			v = fmt.Sprintf("%v, %v", v, s.Value)
		}
	}

	v = fmt.Sprintf("%v, %v", v, bi.GoVersion)

	return v
}

func isAz(s string) bool {
	return bbbfs.IsAz(s)
}

func isHF(s string) bool {
	return bbbfs.IsHF(s)
}

func main() {
	// logLevel will be set from global flag after parsing
	app := &cli.Command{
		Name:    "bbb",
		Usage:   "filesystem helper (local + az:// / https://blob / hf://)",
		Version: version(),
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "loglevel",
				Usage:   "Set log level (debug, info, warn, error)",
				Value:   "info",
				Sources: cli.EnvVars("BBB_LOG_LEVEL"),
			},
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			lvlStr := cmd.String("loglevel")
			var lvl slog.Level
			switch strings.ToLower(lvlStr) {
			case "debug":
				lvl = slog.LevelDebug
			case "info":
				lvl = slog.LevelInfo
			case "warn":
				lvl = slog.LevelWarn
			case "error":
				lvl = slog.LevelError
			default:
				lvl = slog.LevelInfo
			}
			handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
			slog.SetDefault(slog.New(handler))
			slog.Debug("Logger initialized", "level", lvlStr)
			return ctx, nil
		},
		Commands: []*cli.Command{
			{
				Name:      "az",
				Usage:     "Azure Blob related commands",
				UsageText: "bbb az <command>",
				Commands: []*cli.Command{
					{
						Name:      "mkcontainer",
						Usage:     "Create an Azure Blob container",
						UsageText: "bbb az mkcontainer az://account/container",
						Action: func(ctx context.Context, c *cli.Command) error {
							if c.Args().Len() != 1 {
								return fmt.Errorf("mkcontainer: need az://account/container")
							}
							target := c.Args().Get(0)
							if !isAz(target) {
								return fmt.Errorf("mkcontainer: only az:// paths supported")
							}
							ap, err := azblob.Parse(target)
							if err != nil {
								return err
							}
							if ap.Container == "" {
								return fmt.Errorf("mkcontainer: need az://account/container")
							}
							err = azblob.MkContainer(ctx, ap.Account, ap.Container)
							if err != nil {
								return err
							}
							fmt.Printf("Created container %s/%s\n", ap.Account, ap.Container)
							return nil
						},
					},
				},
			},
			{
				Name:      "ls",
				Usage:     "List directory contents",
				UsageText: "bbb ls [-l|--long] [--machine] [-s|--relative] [path]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "l", Aliases: []string{"long"}, Usage: "List information about each file"},
					&cli.BoolFlag{Name: "a", Usage: "include entries starting with ."},
					&cli.BoolFlag{Name: "machine", Usage: "Machine-readable (tab-separated) output"},
					&cli.BoolFlag{Name: "s", Aliases: []string{"relative"}, Usage: "Show relative paths"},
				},
				Action: cmdLS,
			},
			{
				Name:      "ll",
				Aliases:   []string{"du"},
				Usage:     "Alias for 'ls -l' (long listing)",
				UsageText: "bbb ll [-s|--relative] [--machine] [path]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "s", Aliases: []string{"relative"}, Usage: "Show relative paths"},
					&cli.BoolFlag{Name: "machine", Usage: "Machine-readable (tab-separated) output"},
				},
				Action: cmdLL,
			},
			{
				Name:      "lstree",
				Aliases:   []string{"lsr"},
				Usage:     "List all files recursively (files only)",
				UsageText: "bbb lstree [-l|--long] [--machine] [-s|--relative] [path]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "l", Aliases: []string{"long"}, Usage: "List information about each file"},
					&cli.BoolFlag{Name: "machine", Usage: "Machine-readable (tab-separated) output"},
					&cli.BoolFlag{Name: "s", Aliases: []string{"relative"}, Usage: "Show relative paths"},
				},
				Action: cmdLSTree,
			},
			{
				Name:      "llr",
				Usage:     "Alias for 'lstree -l' (recursive long file list)",
				UsageText: "bbb llr [-s|--relative] [--machine] [path]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "s", Aliases: []string{"relative"}, Usage: "Show relative paths"},
					&cli.BoolFlag{Name: "machine", Usage: "Machine-readable (tab-separated) output"},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					return runListTree(ctx, c, true)
				},
			},
			{
				Name:   "cat",
				Usage:  "Print file contents",
				Action: cmdCat,
			},
			{
				Name:   "touch",
				Usage:  "Create an empty file or update its timestamp",
				Action: cmdTouch,
			},
			{
				Name:      "cp",
				Usage:     "Copy files or directories",
				UsageText: "bbb cp [-q|--quiet] [--concurrency N] srcs [srcs ...] dst",
				Aliases:   []string{"cpr", "cptree"},
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "force overwrite"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: 1},
				},
				Action: cmdCP,
			},
			{
				Name:   "edit",
				Usage:  "Open file in $EDITOR (creates if missing)",
				Action: cmdEdit,
			},
			{
				Name:      "rm",
				Usage:     "Remove file(s)",
				UsageText: "bbb rm [-q|--quiet] [--concurrency N] paths [paths ...]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "ignore nonexistent files"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: 1},
				},
				Action: cmdRM,
			},
			{
				Name:      "rmtree",
				Aliases:   []string{"rmr"},
				Usage:     "Remove directory tree",
				UsageText: "bbb rmtree [-q|--quiet] [--concurrency N] path",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: 1},
				},
				Action: cmdRMTree,
			},
			{
				Name:      "share",
				Usage:     "Print a link to open a file in a browser",
				UsageText: "bbb share [path]",
				Action:    cmdShare,
			},
			{
				Name:      "sync",
				Usage:     "Synchronise two directory trees",
				UsageText: "bbb sync [-q|--quiet] [--delete] [-x EXCLUDE|--exclude EXCLUDE] [--concurrency N] src dst",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "dry-run", Usage: "show actions without applying"},
					&cli.BoolFlag{Name: "delete", Usage: "Delete destination files that don't exist in source"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: 1},
					&cli.StringFlag{Name: "x", Aliases: []string{"exclude"}, Usage: "Exclude files matching this regex"},
				},
				Action: cmdSync,
			},
			{
				Name:      "md5sum",
				Usage:     "Compute MD5 checksums (for integrity verification only)",
				UsageText: "bbb md5sum paths [paths ...]",
				Action:    cmdMD5Sum,
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		slog.Error("App error", "err", err)
		os.Exit(1)
	}
	// Remove any stray cli.Before assignment
}

func cmdLS(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdLS called", "args", c.Args().Slice())
	long := c.Bool("l")
	all := c.Bool("a")
	target := "."
	if c.Args().Len() > 0 {
		target = c.Args().Get(0)
	}
	machine := c.Bool("machine")
	relFlag := c.Bool("s")
	parentPath, pattern := splitWildcard(target)
	fs := bbbfs.Resolve(parentPath)
	entries, err := fs.List(ctx, parentPath)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	for _, entry := range entries {
		name := entry.Name
		trimmed := strings.TrimSuffix(name, "/")
		if trimmed == "" {
			continue
		}
		if !all && len(trimmed) > 0 && trimmed[0] == '.' {
			continue
		}
		if pattern != "" {
			matched, err := path.Match(pattern, trimmed)
			if err != nil {
				return err
			}
			if !matched {
				continue
			}
		}
		displayPath := entry.Path
		if relFlag {
			displayPath = trimmed
		}
		if long {
			typ := "-"
			if entry.IsDir {
				typ = "d"
			}
			mod := "-"
			if !entry.ModTime.IsZero() {
				mod = entry.ModTime.Format(time.RFC3339)
			}
			if machine {
				fmt.Printf("%s\t%d\t%s\t%s\n", typ, entry.Size, mod, displayPath)
			} else {
				fmt.Printf("%1s %10d %s %s\n", typ, entry.Size, mod, displayPath)
			}
		} else {
			fmt.Println(displayPath)
		}
	}
	return nil
}

func cmdLSTree(ctx context.Context, c *cli.Command) error { return runListTree(ctx, c, false) }

// runListTree implements recursive file-only listing for lstree and llr.
// longForced is true for llr alias to imply -l.
func runListTree(ctx context.Context, c *cli.Command, longForced bool) error {
	slog.Debug("runListTree called", "args", c.Args().Slice(), "longForced", longForced)
	root := "."
	if c.Args().Len() > 0 {
		root = c.Args().Get(0)
	}
	longFlag := c.Bool("l") || c.Bool("long") || longForced
	machine := c.Bool("machine")
	relFlag := c.Bool("s") || c.Bool("relative")

	parentPath, pattern := splitWildcard(root)
	fs := bbbfs.Resolve(parentPath)
	list, err := fs.ListRecursive(ctx, parentPath)
	if err != nil {
		return err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	var count int64
	for _, entry := range list {
		name := entry.Name
		if name == "" || entry.IsDir {
			continue
		}
		if pattern != "" {
			last := name
			if idx := strings.LastIndex(name, "/"); idx >= 0 {
				last = name[idx+1:]
			}
			matched, err := path.Match(pattern, last)
			if err != nil {
				return err
			}
			if !matched {
				continue
			}
		}
		count++
		display := entry.Path
		if relFlag {
			display = name
		}
		if longFlag {
			mod := "-"
			if !entry.ModTime.IsZero() {
				mod = entry.ModTime.Format(time.RFC3339)
			}
			if machine {
				fmt.Printf("f\t%d\t%s\t%s\n", entry.Size, mod, display)
			} else {
				fmt.Printf("%10d  %s  %s\n", entry.Size, mod, display)
			}
		} else {
			if machine {
				fmt.Printf("f\t%s\n", display)
			} else {
				fmt.Println(display)
			}
		}
	}
	if !machine {
		fmt.Printf("%d files\n", count)
	}
	return nil
}

func splitWildcard(target string) (string, string) {
	if strings.Contains(target, "*") {
		starIdx := strings.Index(target, "*")
		lastSlash := strings.LastIndex(target[:starIdx], "/")
		if lastSlash >= 0 {
			return target[:lastSlash+1], target[lastSlash+1:]
		}
		return target, "*"
	}
	return target, ""
}

func hfSplitWildcard(target string) (string, string) {
	return splitWildcard(target)
}

func cmdCat(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCat called", "args", c.Args().Slice())
	if c.Args().Len() == 0 {
		return fmt.Errorf("cat: need at least one file")
	}
	for i := 0; i < c.Args().Len(); i++ {
		p := c.Args().Get(i)
		if isAz(p) {
			ap, err := azblob.Parse(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
				continue
			}
			reader, err := azblob.DownloadStream(ctx, ap)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
				continue
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				_, err := io.Copy(os.Stdout, r)
				return err
			}); err != nil {
				fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
			}
			continue
		}
		if isHF(p) {
			hfPath, err := hf.Parse(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
				continue
			}
			reader, err := hf.DownloadStream(ctx, hfPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
				continue
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				_, err := io.Copy(os.Stdout, r)
				return err
			}); err != nil {
				fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
			}
			continue
		}
		f, err := os.Open(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
			continue
		}
		_, err = io.Copy(os.Stdout, f)
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
		}
	}
	return nil
}

func cmdTouch(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdTouch called", "args", c.Args().Slice())
	if c.Args().Len() == 0 {
		return fmt.Errorf("touch: need at least one path")
	}
	ts := time.Now()
	for i := 0; i < c.Args().Len(); i++ {
		p := c.Args().Get(i)
		if isAz(p) {
			ap, err := azblob.Parse(p)
			if err != nil {
				return err
			}
			if err := azblob.Touch(ctx, ap); err != nil {
				return err
			}
			continue
		}
		if err := fsops.Touch(p, ts); err != nil {
			return err
		}
	}
	return nil
}

func cmdCP(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCP called", "args", c.Args().Slice())
	if c.Args().Len() < 2 {
		return fmt.Errorf("cp: need srcs dst")
	}
	overwrite := c.Bool("f")
	quiet := c.Bool("q") || c.Bool("quiet")
	// concurrency flag is ignored
	srcs := make([]string, c.Args().Len()-1)
	for i := 0; i < len(srcs); i++ {
		srcs[i] = c.Args().Get(i)
	}
	dst := c.Args().Get(c.Args().Len() - 1)
	if isHF(dst) {
		return fmt.Errorf("cp: hf:// only supported as source")
	}
	dstAz := isAz(dst)
	// Determine if dst is directory (local or Azure)
	isDstDir := false
	if dstAz {
		dap, err := azblob.Parse(dst)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
			isDstDir = true
		}
	} else {
		info, err := os.Stat(dst)
		if err == nil && info.IsDir() {
			isDstDir = true
		} else if strings.HasSuffix(dst, string(os.PathSeparator)) || strings.HasSuffix(dst, "/") {
			isDstDir = true
		}
	}
	for _, src := range srcs {
		srcAz := isAz(src)
		srcHF := isHF(src)
		base := filepath.Base(src)
		var srcAzPath azblob.AzurePath
		if srcAz {
			var err error
			srcAzPath, err = azblob.Parse(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		if srcHF {
			var err error
			hfPath, err := hf.Parse(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if hfPath.File == "" {
				if err := copyHFDir(ctx, hfPath, dst, dstAz, overwrite, quiet); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				continue
			}
			base = hfPath.DefaultFilename()
			if err := copyHFFile(ctx, hfPath, base, dst, dstAz, overwrite, quiet, isDstDir); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			continue
		}
		if srcAz {
			if srcAzPath.IsDirLike() {
				if err := copyTree(ctx, src, dst, overwrite, quiet, "cp"); err != nil {
					fmt.Fprintln(os.Stderr, "cp:", err)
					os.Exit(1)
				}
				continue
			}
		} else if info, err := os.Stat(src); err == nil && info.IsDir() {
			if err := copyTree(ctx, src, dst, overwrite, quiet, "cp"); err != nil {
				fmt.Fprintln(os.Stderr, "cp:", err)
				os.Exit(1)
			}
			continue
		}
		var dstPath string
		if isDstDir {
			if dstAz {
				dap, _ := azblob.Parse(dst)
				if dap.Blob == "" {
					dap.Blob = base
				} else {
					dap.Blob = strings.TrimSuffix(dap.Blob, "/") + "/" + base
				}
				dstPath = dap.String()
			} else {
				dstPath = filepath.Join(dst, base)
			}
		} else {
			dstPath = dst
		}
		// src -> dstPath
		if srcAz && dstAz {
			dap, _ := azblob.Parse(dstPath)
			reader, err := azblob.DownloadStream(ctx, srcAzPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					reader.Close()
					fmt.Fprintln(os.Stderr, "cp: destination exists")
					os.Exit(1)
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return azblob.UploadStream(ctx, dap, r)
			}); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !quiet {
				fmt.Printf("Copied %s -> %s\n", src, dstPath)
			}
		} else if srcAz && !dstAz {
			reader, err := azblob.DownloadStream(ctx, srcAzPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !overwrite {
				if _, err := os.Stat(dstPath); err == nil {
					reader.Close()
					fmt.Fprintln(os.Stderr, "cp: destination exists")
					os.Exit(1)
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return writeStreamToFile(dstPath, r, 0o644)
			}); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !quiet {
				fmt.Printf("Copied %s -> %s\n", src, dstPath)
			}
		} else if !srcAz && dstAz {
			dap, _ := azblob.Parse(dstPath)
			reader, err := os.Open(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					reader.Close()
					fmt.Fprintln(os.Stderr, "cp: destination exists")
					os.Exit(1)
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return azblob.UploadStream(ctx, dap, r)
			}); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !quiet {
				fmt.Printf("Copied %s -> %s\n", src, dstPath)
			}
		} else {
			if err := fsops.CopyFile(src, dstPath, overwrite); err != nil {
				fmt.Fprintln(os.Stderr, "cp:", err)
				os.Exit(1)
			}
			if !quiet {
				fmt.Printf("Copied %s -> %s\n", src, dstPath)
			}
		}
	}
	return nil
}

func copyTree(ctx context.Context, src, dst string, overwrite, quiet bool, errPrefix string) error {
	if isAz(src) || isAz(dst) {
		// naive recursive copy via listing + per-blob cp
		srcAz, dstAz := isAz(src), isAz(dst)
		if srcAz && dstAz {
			sap, _ := azblob.Parse(src)
			dap, _ := azblob.Parse(dst)
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				return err
			}
			var hadErrors bool
			for _, bm := range list {
				reader, err := azblob.DownloadStream(ctx, sap.Child(bm.Name))
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s: %v\n", errPrefix, bm.Name, err)
					hadErrors = true
					continue
				}
				if !overwrite {
					if _, err := azblob.HeadBlob(ctx, dap.Child(bm.Name)); err == nil {
						reader.Close()
						continue
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return azblob.UploadStream(ctx, dap.Child(bm.Name), r)
				}); err != nil {
					fmt.Fprintf(os.Stderr, "%s: upload %s: %v\n", errPrefix, bm.Name, err)
					hadErrors = true
					continue
				}
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(bm.Name).String(), dap.Child(bm.Name).String())
				}
			}
			if hadErrors {
				return fmt.Errorf("%s: one or more files failed to copy", errPrefix)
			}
			return nil
		}
		if srcAz && !dstAz { // Azure -> local
			sap, _ := azblob.Parse(src)
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				return err
			}
			var hadErrors bool
			for _, bm := range list {
				reader, err := azblob.DownloadStream(ctx, sap.Child(bm.Name))
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s: %v\n", errPrefix, bm.Name, err)
					hadErrors = true
					continue
				}
				outPath := filepath.Join(dst, bm.Name)
				if !overwrite {
					if _, err := os.Stat(outPath); err == nil {
						reader.Close()
						continue
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return writeStreamToFile(outPath, r, 0o644)
				}); err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s: %v\n", errPrefix, bm.Name, err)
					hadErrors = true
					continue
				}
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(bm.Name).String(), outPath)
				}
			}
			if hadErrors {
				return fmt.Errorf("%s: one or more files failed to copy", errPrefix)
			}
			return nil
		}
		if !srcAz && dstAz { // local -> Azure
			dap, _ := azblob.Parse(dst)
			// walk local
			var hadErrors bool
			if err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s: %v\n", errPrefix, p, err)
					hadErrors = true
					return nil
				}
				if d.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(src, p)
				reader, err := os.Open(p)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %s: %v\n", errPrefix, rel, err)
					hadErrors = true
					return nil
				}
				if !overwrite {
					if _, err := azblob.HeadBlob(ctx, dap.Child(rel)); err == nil {
						reader.Close()
						return nil
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return azblob.UploadStream(ctx, dap.Child(rel), r)
				}); err != nil {
					fmt.Fprintf(os.Stderr, "%s: upload %s: %v\n", errPrefix, rel, err)
					hadErrors = true
					return nil
				}
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", p, dap.Child(rel).String())
				}
				return nil
			}); err != nil {
				return err
			}
			if hadErrors {
				return fmt.Errorf("%s: one or more files failed to copy", errPrefix)
			}
			return nil
		}
	}
	if err := fsops.CopyTree(src, dst, overwrite); err != nil {
		return err
	}
	return nil
}

func copyHFFile(ctx context.Context, hfPath hf.Path, base, dst string, dstAz, overwrite, quiet, dstDir bool) error {
	dstPath, err := resolveDstPath(dst, dstAz, base, dstDir)
	if err != nil {
		return err
	}
	if dstAz {
		reader, err := hf.DownloadStream(ctx, hfPath)
		if err != nil {
			return err
		}
		dap, err := azblob.Parse(dstPath)
		if err != nil {
			reader.Close()
			return err
		}
		if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
			reader.Close()
			return errors.New("cp: destination must be a blob path")
		}
		if !overwrite {
			if _, err := azblob.HeadBlob(ctx, dap); err == nil {
				reader.Close()
				return errors.New("cp: destination exists")
			}
		}
		if err := withReadCloser(reader, func(r io.Reader) error {
			return azblob.UploadStream(ctx, dap, r)
		}); err != nil {
			return err
		}
	} else {
		if !overwrite {
			if _, err := os.Stat(dstPath); err == nil {
				return errors.New("cp: destination exists")
			}
		}
		reader, err := hf.DownloadStream(ctx, hfPath)
		if err != nil {
			return err
		}
		if err := withReadCloser(reader, func(r io.Reader) error {
			return writeStreamToFile(dstPath, r, 0o644)
		}); err != nil {
			return err
		}
	}
	if !quiet {
		fmt.Printf("Copied %s -> %s\n", hfPath.String(), dstPath)
	}
	return nil
}

func copyHFDir(ctx context.Context, hfPath hf.Path, dst string, dstAz, overwrite, quiet bool) error {
	files, err := hf.ListFiles(ctx, hfPath)
	if err != nil {
		return err
	}
	for _, file := range files {
		filePath := hf.Path{Repo: hfPath.Repo, File: file}
		reader, err := hf.DownloadStream(ctx, filePath)
		if err != nil {
			return err
		}
		dstPath, err := resolveDstPath(dst, dstAz, file, true)
		if err != nil {
			reader.Close()
			return err
		}
		if dstAz {
			dap, err := azblob.Parse(dstPath)
			if err != nil {
				reader.Close()
				return err
			}
			if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
				reader.Close()
				return errors.New("cp: destination must be a blob path")
			}
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					reader.Close()
					continue
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return azblob.UploadStream(ctx, dap, r)
			}); err != nil {
				return err
			}
		} else {
			if !overwrite {
				if _, err := os.Stat(dstPath); err == nil {
					reader.Close()
					continue
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return writeStreamToFile(dstPath, r, 0o644)
			}); err != nil {
				return err
			}
		}
		if !quiet {
			fmt.Printf("Copied %s -> %s\n", filePath.String(), dstPath)
		}
	}
	return nil
}

func writeStreamToFile(dstPath string, reader io.Reader, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(dstFile, reader)
	closeErr := dstFile.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

func withReadCloser(reader io.ReadCloser, fn func(io.Reader) error) error {
	defer reader.Close()
	return fn(reader)
}

func resolveDstPath(dst string, dstAz bool, base string, mustBeDir bool) (string, error) {
	if dstAz {
		dap, err := azblob.Parse(dst)
		if err != nil {
			return "", err
		}
		if mustBeDir && dap.Blob != "" && !strings.HasSuffix(dap.Blob, "/") {
			dap.Blob += "/"
		}
		if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
			if dap.Blob == "" {
				dap.Blob = base
			} else {
				dap.Blob = strings.TrimSuffix(dap.Blob, "/") + "/" + base
			}
			return dap.String(), nil
		}
		if mustBeDir {
			return "", errors.New("cp: destination must be a directory")
		}
		return dst, nil
	}
	info, err := os.Stat(dst)
	if err == nil && info.IsDir() {
		return filepath.Join(dst, base), nil
	}
	if strings.HasSuffix(dst, string(os.PathSeparator)) || strings.HasSuffix(dst, "/") {
		return filepath.Join(dst, base), nil
	}
	if mustBeDir {
		return "", errors.New("cp: destination must be a directory")
	}
	return dst, nil
}
func cmdEdit(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdEdit called", "args", c.Args().Slice())
	if c.Args().Len() != 1 {
		return fmt.Errorf("edit: need file path")
	}
	path := c.Args().Get(0)
	if _, err := os.Stat(path); err != nil {
		// create empty file
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if f, err := os.OpenFile(path, os.O_CREATE, 0o644); err == nil {
			f.Close()
		} else {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}
	cmd := exec.Command(editor, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "edit:", err)
		os.Exit(1)
	}
	return nil
}

func cmdRM(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdRM called", "args", c.Args().Slice())
	force := c.Bool("f")
	quiet := c.Bool("q") || c.Bool("quiet")
	// concurrency flag is ignored
	if c.Args().Len() == 0 {
		return fmt.Errorf("rm: need at least one path")
	}
	for i := 0; i < c.Args().Len(); i++ {
		p := c.Args().Get(i)
		if isAz(p) {
			ap, err := azblob.Parse(p)
			if err != nil {
				if force {
					continue
				} else {
					return err
				}
			}
			if err := azblob.Delete(ctx, ap); err != nil {
				if force && strings.Contains(strings.ToLower(err.Error()), "notfound") {
					continue
				}
				return err
			}
			if !quiet {
				fmt.Printf("Deleted %s\n", p)
			}
		} else {
			if err := os.Remove(p); err != nil {
				if force && os.IsNotExist(err) {
					continue
				}
				return err
			}
			if !quiet {
				fmt.Printf("Deleted %s\n", p)
			}
		}
	}
	return nil
}

func cmdRMTree(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdRMTree called", "args", c.Args().Slice())
	quiet := c.Bool("q") || c.Bool("quiet")
	// concurrency flag is ignored
	if c.Args().Len() != 1 {
		return fmt.Errorf("rmtree: need directory root")
	}
	root := c.Args().Get(0)
	if isAz(root) {
		ap, err := azblob.Parse(root)
		if err != nil {
			return err
		}
		list, err := azblob.ListRecursive(ctx, ap)
		if err != nil {
			return err
		}
		for _, bm := range list {
			if bm.Name == "" || strings.HasSuffix(bm.Name, "/") {
				continue
			}
			if err := azblob.Delete(ctx, ap.Child(bm.Name)); err != nil {
				fmt.Fprintf(os.Stderr, "rmtree: %s: %v\n", bm.Name, err)
			} else if !quiet {
				fmt.Printf("Deleted %s\n", ap.Child(bm.Name).String())
			}
		}
		return nil
	}
	err := os.RemoveAll(root)
	if err == nil && !quiet {
		fmt.Printf("Deleted %s\n", root)
	}
	return err
}

func cmdShare(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdShare called", "args", c.Args().Slice())
	if c.Args().Len() != 1 {
		return fmt.Errorf("share: need exactly one path")
	}
	p := c.Args().Get(0)
	// For Azure paths, print a browser link (e.g., https://portal.azure.com/#blade/Microsoft_Azure_Storage/ContainerMenuBlade/...) or a direct blob URL if public
	if isAz(p) {
		ap, err := azblob.Parse(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "share: %s: %v\n", p, err)
			return err
		}
		// Example: https://portal.azure.com/#blade/Microsoft_Azure_Storage/ContainerMenuBlade/overview/storageaccount/%s/container/%s/path/%s
		// Or direct blob link if public: https://%s.blob.core.windows.net/%s/%s
		portal := fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Storage/ContainerMenuBlade/overview/storageaccount/%s/container/%s/path/%s", ap.Account, ap.Container, ap.Blob)
		direct := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", ap.Account, ap.Container, ap.Blob)
		fmt.Println("Azure Portal:", portal)
		fmt.Println("Direct Blob (if public):", direct)
		return nil
	}
	// For local files, print a file:// link
	abs, err := filepath.Abs(p)
	if err != nil {
		fmt.Fprintf(os.Stderr, "share: %s: %v\n", p, err)
		return err
	}
	fmt.Println("file://" + abs)
	return nil
}

func syncHFFiles(ctx context.Context, hfPath hf.Path, excludeMatch func(string) bool) ([]string, error) {
	if hfPath.File != "" {
		return nil, errors.New("sync: hf:// path must target repository root, not individual files")
	}
	files, err := hf.ListFiles(ctx, hfPath)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(files))
	for _, file := range files {
		if excludeMatch(file) {
			continue
		}
		out = append(out, file)
	}
	return out, nil
}

func cmdSync(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdSync called", "args", c.Args().Slice())
	if c.Args().Len() != 2 {
		return fmt.Errorf("sync: need src dst")
	}
	dry := c.Bool("dry-run")
	del := c.Bool("delete")
	quiet := c.Bool("q") || c.Bool("quiet")
	exclude := c.String("x")
	// concurrency flag is ignored
	src, dst := c.Args().Get(0), c.Args().Get(1)
	if isHF(dst) {
		return fmt.Errorf("sync: hf:// only supported as source")
	}
	srcHF := isHF(src)
	if srcHF && !isAz(dst) {
		return fmt.Errorf("sync: hf:// only supported with az:// destination")
	}
	var hfPath hf.Path
	if srcHF {
		var err error
		hfPath, err = hf.Parse(src)
		if err != nil {
			return fmt.Errorf("sync: %w", err)
		}
		if hfPath.File != "" {
			return errors.New("sync: hf:// path must target repository root, not individual files")
		}
	}
	//
	var excludeMatch func(string) bool
	if exclude != "" {
		// Use Go's regexp for matching
		re, err := regexp.Compile(exclude)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sync: invalid exclude regex: %v\n", err)
			return err
		}
		excludeMatch = func(rel string) bool { return re.MatchString(rel) }
	} else {
		excludeMatch = func(string) bool { return false }
	}
	if isAz(src) || isAz(dst) || srcHF {
		srcAz, dstAz := isAz(src), isAz(dst)
		// Build src file list
		type item struct {
			rel  string
			size int64
		}
		var files []item
		if srcAz {
			sap, err := azblob.Parse(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for _, bm := range list {
				if bm.Name == "" || excludeMatch(bm.Name) {
					continue
				}
				files = append(files, item{rel: bm.Name, size: bm.Size})
			}
		} else if srcHF {
			list, err := syncHFFiles(ctx, hfPath, excludeMatch)
			if err != nil {
				return err
			}
			for _, name := range list {
				files = append(files, item{rel: name})
			}
		} else {
			filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(src, p)
				if excludeMatch(rel) {
					return nil
				}
				info, _ := d.Info()
				files = append(files, item{rel: rel, size: info.Size()})
				return nil
			})
		}
		// Copy loop
		for _, f := range files {
			sPath := f.rel
			if srcAz && dstAz {
				sap, _ := azblob.Parse(src)
				dap, _ := azblob.Parse(dst)
				reader, err := azblob.DownloadStream(ctx, sap.Child(sPath))
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				if dry {
					if !quiet {
						fmt.Println("COPY", sap.Child(sPath).String(), "->", dap.Child(sPath).String())
					}
					reader.Close()
					continue
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return azblob.UploadStream(ctx, dap.Child(sPath), r)
				}); err != nil {
					fmt.Fprintf(os.Stderr, "sync upload: %s: %v\n", sPath, err)
				} else if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(sPath).String(), dap.Child(sPath).String())
				}
				continue
			}
			if srcHF && dstAz {
				dap, err := azblob.Parse(dst)
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", dst, err)
					return err
				}
				hfFile := hf.Path{Repo: hfPath.Repo, File: sPath}
				if dry {
					if !quiet {
						fmt.Println("COPY", hfFile.String(), "->", dap.Child(sPath).String())
					}
					continue
				}
				data, err := hf.Download(ctx, hfFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				if err := azblob.Upload(ctx, dap.Child(sPath), data); err != nil {
					fmt.Fprintf(os.Stderr, "sync upload: %s: %v\n", sPath, err)
				} else if !quiet {
					fmt.Printf("Copied %s -> %s\n", hfFile.String(), dap.Child(sPath).String())
				}
				continue
			}
			if srcAz && !dstAz {
				sap, _ := azblob.Parse(src)
				reader, err := azblob.DownloadStream(ctx, sap.Child(sPath))
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				out := filepath.Join(dst, sPath)
				if dry {
					if !quiet {
						fmt.Println("COPY", sap.Child(sPath).String(), "->", out)
					}
					reader.Close()
					continue
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return writeStreamToFile(out, r, 0o644)
				}); err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(sPath).String(), out)
				}
				continue
			}
			if !srcAz && dstAz {
				dap, _ := azblob.Parse(dst)
				reader, err := os.Open(filepath.Join(src, sPath))
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				if dry {
					if !quiet {
						fmt.Println("COPY", filepath.Join(src, sPath), "->", dap.Child(sPath).String())
					}
					reader.Close()
					continue
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return azblob.UploadStream(ctx, dap.Child(sPath), r)
				}); err != nil {
					fmt.Fprintf(os.Stderr, "sync upload: %s: %v\n", sPath, err)
				} else if !quiet {
					fmt.Printf("Copied %s -> %s\n", filepath.Join(src, sPath), dap.Child(sPath).String())
				}
				continue
			}
		}
		// delete phase not implemented for cloud combos yet
		return nil
	}
	// collect source files
	var srcFiles []string
	filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(src, p)
		if excludeMatch(rel) {
			return nil
		}
		srcFiles = append(srcFiles, rel)
		return nil
	})
	// build set for deletion check
	srcSet := make(map[string]struct{}, len(srcFiles))
	for _, r := range srcFiles {
		srcSet[r] = struct{}{}
	}
	// copy/update
	for _, r := range srcFiles {
		sPath := filepath.Join(src, r)
		dPath := filepath.Join(dst, r)
		needCopy := true
		if infoDst, err := os.Stat(dPath); err == nil {
			infoSrc, _ := os.Stat(sPath)
			if infoSrc.Size() == infoDst.Size() && infoSrc.ModTime().Equal(infoDst.ModTime()) {
				needCopy = false
			}
		}
		if needCopy {
			if dry {
				if !quiet {
					fmt.Println("COPY", sPath, "->", dPath)
				}
			} else {
				if err := fsops.CopyFile(sPath, dPath, true); err != nil {
					fmt.Fprintf(os.Stderr, "sync copy: %s: %v\n", r, err)
				} else {
					// preserve modtime
					if info, err := os.Stat(sPath); err == nil {
						os.Chtimes(dPath, info.ModTime(), info.ModTime())
					}
					if !quiet {
						fmt.Printf("Copied %s -> %s\n", sPath, dPath)
					}
				}
			}
		}
	}
	if del {
		filepath.WalkDir(dst, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dst, p)
			if excludeMatch(rel) {
				return nil
			}
			if _, ok := srcSet[rel]; !ok {
				if dry {
					if !quiet {
						fmt.Println("DELETE", p)
					}
				} else {
					os.Remove(p)
					if !quiet {
						fmt.Printf("Deleted %s\n", p)
					}
				}
			}
			return nil
		})
	}
	return nil
}

func cmdMD5Sum(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdMD5Sum called", "args", c.Args().Slice())
	if c.Args().Len() == 0 {
		return fmt.Errorf("md5sum: need at least one path")
	}
	for i := 0; i < c.Args().Len(); i++ {
		p := c.Args().Get(i)
		reader, err := bbbfs.Resolve(p).Read(ctx, p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "md5sum: %s: %v\n", p, err)
			continue
		}
		printMD5Sum(reader, p)
	}
	return nil
}

func printMD5Sum(r io.ReadCloser, label string) {
	if err := writeMD5SumReadCloser(r, label); err != nil {
		fmt.Fprintf(os.Stderr, "md5sum: %s: %v\n", label, err)
	}
}

func writeMD5SumReadCloser(r io.ReadCloser, label string) error {
	defer r.Close()
	return writeMD5Sum(r, label)
}

func writeMD5Sum(r io.Reader, label string) error {
	hasher := md5.New()
	if _, err := io.Copy(hasher, r); err != nil {
		return err
	}
	fmt.Printf("%x  %s\n", hasher.Sum(nil), label)
	return nil
}

// ll: long listing for Azure paths, like py version
func cmdLL(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdLL called", "args", c.Args().Slice())
	target := "."
	if c.Args().Len() > 0 {
		target = c.Args().Get(0)
	}
	machine := c.Bool("machine")
	relFlag := c.Bool("s")
	parentPath, pattern := splitWildcard(target)
	fs := bbbfs.Resolve(parentPath)
	list, err := fs.List(ctx, parentPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var totalSize int64
	var count int
	for _, entry := range list {
		name := entry.Name
		if name == "" || entry.IsDir {
			continue
		}
		if pattern != "" {
			matched, err := path.Match(pattern, strings.TrimSuffix(name, "/"))
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !matched {
				continue
			}
		}
		sizeMiB := float64(entry.Size) / (1024 * 1024)
		mod := "-"
		if !entry.ModTime.IsZero() {
			mod = entry.ModTime.Format(time.RFC3339)
		}
		display := entry.Path
		if relFlag {
			display = strings.TrimSuffix(name, "/")
		}
		if machine {
			fmt.Printf("f\t%d\t%s\t%s\n", entry.Size, mod, display)
		} else {
			fmt.Printf("%10.1f MiB  %s  %s\n", sizeMiB, mod, display)
		}
		totalSize += entry.Size
		count++
	}
	if !machine {
		fmt.Printf("Listed %d files summing to %d bytes (%.1f MiB)\n", count, totalSize, float64(totalSize)/(1024*1024))
	}
	return nil
}
