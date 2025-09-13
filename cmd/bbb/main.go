package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"log/slog"

	"github.com/urfave/cli/v3"

	"github.com/tg123/bbb/pkg/azblob"
	"github.com/tg123/bbb/pkg/fsops"
)

func isAz(s string) bool { return strings.HasPrefix(s, "az://") }

func main() {
	// logLevel will be set from global flag after parsing
	app := &cli.Command{
		Name:  "bbb",
		Usage: "filesystem helper (local + az://)",
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
				Name:      "cp",
				Usage:     "Copy files",
				UsageText: "bbb cp [-q|--quiet] [--concurrency N] srcs [srcs ...] dst",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "force overwrite"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: 1},
				},
				Action: cmdCP,
			},
			{
				Name:      "cptree",
				Aliases:   []string{"cpr"},
				Usage:     "Copy directories recursively",
				UsageText: "bbb cptree [-q|--quiet] [--concurrency N] src dst",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "force overwrite"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: 1},
				},
				Action: cmdCPTree,
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
	slog.Debug("cmdLSTree called", "args", c.Args().Slice())
	long := c.Bool("l")
	all := c.Bool("a")
	target := "."
	if c.Args().Len() > 0 {
		target = c.Args().Get(0)
	}
	machine := c.Bool("machine")
	relFlag := c.Bool("s")
	if isAz(target) {
		ap, err := azblob.Parse(target)
		if err != nil {
			return err
		}
		if ap.Blob != "" && !strings.HasSuffix(ap.Blob, "/") {
			size, err := azblob.HeadBlob(ctx, ap)
			if err != nil {
				return err
			}
			name := filepath.Base(ap.Blob)
			if machine {
				fmt.Printf("f\t%d\t-\t%s\n", size, name)
			} else if long {
				fmt.Printf("- %10d %s %s\n", size, "-", name)
			} else {
				fmt.Println(name)
			}
			return nil
		}
		list, err := azblob.List(ctx, ap)
		if err != nil {
			return err
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		for _, bm := range list {
			name := bm.Name
			if name == "" {
				continue
			}
			if !all && name[0] == '.' {
				continue
			}
			fullpath := fmt.Sprintf("az://%s/%s/%s", ap.Account, ap.Container, path.Join(ap.Blob, name))
			fullpath = strings.TrimSuffix(fullpath, "/")
			displayPath := fullpath
			if relFlag {
				displayPath = name
				displayPath = strings.TrimSuffix(displayPath, "/")
			}
			if long {
				typ := "-"
				if strings.HasSuffix(name, "/") || (bm.Size == 0 && strings.HasSuffix(ap.Blob, "/")) {
					typ = "d"
				}
				if machine {
					fmt.Printf("%s\t%d\t-\t%s\n", typ, bm.Size, displayPath)
				} else {
					fmt.Printf("%1s %10d %s %s\n", typ, bm.Size, "-", displayPath)
				}
			} else {
				fmt.Println(displayPath)
			}
		}
		return nil
	}
	entries, err := fsops.List(target)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, e := range entries {
		name := e.Name()
		if !all && name != "." && name != ".." && name[0] == '.' {
			continue
		}
		if long {
			info, err := e.Info()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
				continue
			}
			mod := info.ModTime().Format(time.RFC3339)
			size := info.Size()
			typ := "-"
			if info.IsDir() {
				typ = "d"
			}
			outName := name
			if relFlag {
				outName = filepath.Clean(name)
			}
			if machine {
				fmt.Printf("%s\t%d\t%s\t%s\n", typ, size, mod, outName)
			} else {
				fmt.Printf("%1s %10d %s %s\n", typ, size, mod, outName)
			}
		} else {
			outName := name
			if relFlag {
				outName = filepath.Clean(name)
			}
			fmt.Println(outName)
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

	if isAz(root) {
		ap, err := azblob.Parse(root)
		if err != nil {
			return err
		}
		list, err := azblob.ListRecursive(ctx, ap)
		if err != nil {
			return err
		}
		prefix := ap.Blob
		if relFlag && prefix != "" && !strings.HasSuffix(prefix, "/") {
			prefix += "/"
		}
		var count int64
		for _, bm := range list {
			name := bm.Name
			if name == "" || strings.HasSuffix(name, "/") { // skip directory markers
				continue
			}
			count++
			display := name
			if relFlag && prefix != "" && strings.HasPrefix(display, prefix) {
				display = strings.TrimPrefix(display, prefix)
			}
			if longFlag {
				// We have size; modtime not available quickly so use '-'
				if machine {
					fmt.Printf("f\t%d\t-\t%s\n", bm.Size, display)
				} else {
					fmt.Printf("%10d  -  %s\n", bm.Size, display)
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

	// Local
	var count int64
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		count++
		display := p
		if relFlag {
			if root == "." {
				display = p
			} else if rel, rerr := filepath.Rel(root, p); rerr == nil {
				display = rel
			}
		}
		if longFlag {
			info, serr := os.Stat(p)
			var size int64
			var modStr string = "-"
			if serr == nil {
				size = info.Size()
				modStr = info.ModTime().Format(time.RFC3339)
			}
			if machine {
				fmt.Printf("f\t%d\t%s\t%s\n", size, modStr, display)
			} else {
				fmt.Printf("%10d  %s  %s\n", size, modStr, display)
			}
		} else {
			if machine {
				fmt.Printf("f\t%s\n", display)
			} else {
				fmt.Println(display)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !machine {
		fmt.Printf("%d files\n", count)
	}
	return nil
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
			data, err := azblob.Download(ctx, ap)
			if err != nil {
				fmt.Fprintf(os.Stderr, "cat: %s: %v\n", p, err)
				continue
			}
			os.Stdout.Write(data)
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
		var dstPath string
		if isDstDir {
			base := filepath.Base(src)
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
			sap, _ := azblob.Parse(src)
			dap, _ := azblob.Parse(dstPath)
			data, err := azblob.Download(ctx, sap)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					fmt.Fprintln(os.Stderr, "cp: destination exists")
					os.Exit(1)
				}
			}
			if err := azblob.Upload(ctx, dap, data); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !quiet {
				fmt.Printf("Copied %s -> %s\n", src, dstPath)
			}
		} else if srcAz && !dstAz {
			sap, _ := azblob.Parse(src)
			data, err := azblob.Download(ctx, sap)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !overwrite {
				if _, err := os.Stat(dstPath); err == nil {
					fmt.Fprintln(os.Stderr, "cp: destination exists")
					os.Exit(1)
				}
			}
			if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := os.WriteFile(dstPath, data, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !quiet {
				fmt.Printf("Copied %s -> %s\n", src, dstPath)
			}
		} else if !srcAz && dstAz {
			dap, _ := azblob.Parse(dstPath)
			data, err := os.ReadFile(src)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					fmt.Fprintln(os.Stderr, "cp: destination exists")
					os.Exit(1)
				}
			}
			if err := azblob.Upload(ctx, dap, data); err != nil {
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

func cmdCPTree(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCPTree called", "args", c.Args().Slice())
	if c.Args().Len() != 2 {
		return fmt.Errorf("cptree: need src dst")
	}
	overwrite := c.Bool("f")
	quiet := c.Bool("q") || c.Bool("quiet")
	// concurrency flag is ignored
	src, dst := c.Args().Get(0), c.Args().Get(1)
	if isAz(src) || isAz(dst) {
		// naive recursive copy via listing + per-blob cp
		srcAz, dstAz := isAz(src), isAz(dst)
		if srcAz && dstAz {
			sap, _ := azblob.Parse(src)
			dap, _ := azblob.Parse(dst)
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for _, bm := range list {
				data, err := azblob.Download(ctx, sap.Child(bm.Name))
				if err != nil {
					fmt.Fprintf(os.Stderr, "cptree: %s: %v\n", bm.Name, err)
					continue
				}
				if err := azblob.Upload(ctx, dap.Child(bm.Name), data); err != nil {
					fmt.Fprintf(os.Stderr, "cptree: upload %s: %v\n", bm.Name, err)
				}
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(bm.Name).String(), dap.Child(bm.Name).String())
				}
			}
			return nil
		}
		if srcAz && !dstAz { // Azure -> local
			sap, _ := azblob.Parse(src)
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			for _, bm := range list {
				data, err := azblob.Download(ctx, sap.Child(bm.Name))
				if err != nil {
					fmt.Fprintf(os.Stderr, "cptree: %s: %v\n", bm.Name, err)
					continue
				}
				outPath := filepath.Join(dst, bm.Name)
				if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				if !overwrite {
					if _, err := os.Stat(outPath); err == nil {
						continue
					}
				}
				os.WriteFile(outPath, data, 0o644)
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(bm.Name).String(), outPath)
				}
			}
			return nil
		}
		if !srcAz && dstAz { // local -> Azure
			dap, _ := azblob.Parse(dst)
			// walk local
			filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				rel, _ := filepath.Rel(src, p)
				data, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				if err := azblob.Upload(ctx, dap.Child(rel), data); err != nil {
					fmt.Fprintf(os.Stderr, "cptree: upload %s: %v\n", rel, err)
				}
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", p, dap.Child(rel).String())
				}
				return nil
			})
			return nil
		}
	}
	if err := fsops.CopyTree(src, dst, overwrite); err != nil {
		fmt.Fprintln(os.Stderr, "cptree:", err)
		os.Exit(1)
	}
	return nil
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
	if isAz(src) || isAz(dst) {
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
				data, err := azblob.Download(ctx, sap.Child(sPath))
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				if dry {
					if !quiet {
						fmt.Println("COPY", sap.Child(sPath).String(), "->", dap.Child(sPath).String())
					}
					continue
				}
				if err := azblob.Upload(ctx, dap.Child(sPath), data); err != nil {
					fmt.Fprintf(os.Stderr, "sync upload: %s: %v\n", sPath, err)
				} else if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(sPath).String(), dap.Child(sPath).String())
				}
				continue
			}
			if srcAz && !dstAz {
				sap, _ := azblob.Parse(src)
				data, err := azblob.Download(ctx, sap.Child(sPath))
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				out := filepath.Join(dst, sPath)
				if dry {
					if !quiet {
						fmt.Println("COPY", sap.Child(sPath).String(), "->", out)
					}
					continue
				}
				if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
					fmt.Fprintf(os.Stderr, "sync mkdir: %v\n", err)
					continue
				}
				os.WriteFile(out, data, 0o644)
				if !quiet {
					fmt.Printf("Copied %s -> %s\n", sap.Child(sPath).String(), out)
				}
				continue
			}
			if !srcAz && dstAz {
				dap, _ := azblob.Parse(dst)
				data, err := os.ReadFile(filepath.Join(src, sPath))
				if err != nil {
					fmt.Fprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					continue
				}
				if dry {
					if !quiet {
						fmt.Println("COPY", filepath.Join(src, sPath), "->", dap.Child(sPath).String())
					}
					continue
				}
				if err := azblob.Upload(ctx, dap.Child(sPath), data); err != nil {
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

// ll: long listing for Azure paths, like py version
func cmdLL(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdLL called", "args", c.Args().Slice())
	target := "."
	if c.Args().Len() > 0 {
		target = c.Args().Get(0)
	}
	machine := c.Bool("machine")
	relFlag := c.Bool("s")
	if isAz(target) {
		ap, err := azblob.Parse(target)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ctx := context.Background()
		list, err := azblob.List(ctx, ap)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var totalSize int64
		var count int
		for _, bm := range list {
			name := bm.Name
			if name == "" || strings.HasSuffix(name, "/") {
				continue // skip directories
			}
			fullpath := fmt.Sprintf("az://%s/%s/%s", ap.Account, ap.Container, path.Join(ap.Blob, name))
			fullpath = strings.TrimSuffix(fullpath, "/")
			sizeMiB := float64(bm.Size) / (1024 * 1024)
			mod := "-" // Placeholder, modtime not available
			display := fullpath
			if relFlag {
				display = strings.TrimSuffix(name, "/")
			}
			if machine {
				fmt.Printf("f\t%d\t%s\t%s\n", bm.Size, mod, display)
			} else {
				fmt.Printf("%10.1f MiB  %s  %s\n", sizeMiB, mod, display)
			}
			totalSize += bm.Size
			count++
		}
		if !machine {
			fmt.Printf("Listed %d files summing to %d bytes (%.1f MiB)\n", count, totalSize, float64(totalSize)/(1024*1024))
		}
		return nil
	}
	// fallback: local
	entries, err := fsops.List(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var totalSize int64
	var count int
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.IsDir() {
			continue
		}
		sizeMiB := float64(info.Size()) / (1024 * 1024)
		mod := info.ModTime().Format(time.RFC3339)
		display := e.Name()
		if relFlag {
			display = filepath.Clean(e.Name())
		}
		if machine {
			fmt.Printf("f\t%d\t%s\t%s\n", info.Size(), mod, display)
		} else {
			fmt.Printf("%10.1f MiB  %s  %s\n", sizeMiB, mod, display)
		}
		totalSize += info.Size()
		count++
	}
	if !machine {
		fmt.Printf("Listed %d files summing to %d bytes (%.1f MiB)\n", count, totalSize, float64(totalSize)/(1024*1024))
	}
	return nil
}
