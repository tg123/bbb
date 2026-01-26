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
	"sync"
	"time"

	"log/slog"

	"github.com/urfave/cli/v3"

	"github.com/tg123/bbb/internal/azblob"
	"github.com/tg123/bbb/internal/fsops"
	"github.com/tg123/bbb/internal/hf"
)

var mainver string = "(devel)"

const hfScheme = "hf://"

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
	if strings.HasPrefix(s, "az://") {
		return true
	}
	return azblob.IsBlobURL(s)
}

func isHF(s string) bool {
	return strings.HasPrefix(s, hfScheme)
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

func normalizeHFPrefix(prefix string) string {
	for strings.HasPrefix(prefix, "/") {
		prefix = strings.TrimPrefix(prefix, "/")
	}
	if prefix == "" {
		return ""
	}
	prefix = path.Clean(prefix)
	if prefix == "." {
		return ""
	}
	return prefix
}

func hfFilterFiles(files []string, prefix string) []string {
	prefix = normalizeHFPrefix(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	out := make([]string, 0, len(files))
	for _, file := range files {
		if file == "" {
			continue
		}
		if prefix != "" {
			if !strings.HasPrefix(file, prefix) {
				continue
			}
			file = strings.TrimPrefix(file, prefix)
			if file == "" {
				continue
			}
		}
		out = append(out, file)
	}
	return out
}

func hfListEntries(files []string, prefix string) []string {
	seen := map[string]struct{}{}
	for _, file := range hfFilterFiles(files, prefix) {
		parts := strings.SplitN(file, "/", 2)
		name := parts[0]
		if name == "" {
			continue
		}
		if len(parts) > 1 {
			name += "/"
		}
		seen[name] = struct{}{}
	}
	entries := make([]string, 0, len(seen))
	for name := range seen {
		entries = append(entries, name)
	}
	sort.Strings(entries)
	return entries
}

func hfSplitWildcard(target string) (string, string) {
	parentPath := target
	var pattern string
	if strings.Contains(target, "*") {
		starIdx := strings.Index(target, "*")
		lastSlash := strings.LastIndex(target[:starIdx], "/")
		if lastSlash >= len(hfScheme) {
			parentPath = target[:lastSlash+1]
			pattern = target[lastSlash+1:]
		}
	}
	return parentPath, pattern
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
	if isHF(target) {
		parentPath, pattern := hfSplitWildcard(target)
		hp, err := hf.Parse(parentPath)
		if err != nil {
			return err
		}
		hp.File = normalizeHFPrefix(hp.File)
		files, err := hf.ListFiles(ctx, hf.Path{Repo: hp.Repo})
		if err != nil {
			return err
		}
		entries := hfListEntries(files, hp.File)
		for _, name := range entries {
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
			fullFile := path.Join(hp.File, trimmed)
			fullpath := hf.Path{Repo: hp.Repo, File: fullFile}.String()
			displayPath := fullpath
			if relFlag {
				displayPath = trimmed
			}
			if long {
				typ := "-"
				if strings.HasSuffix(name, "/") {
					typ = "d"
				}
				if machine {
					fmt.Printf("%s\t%d\t-\t%s\n", typ, 0, displayPath)
				} else {
					fmt.Printf("%1s %10d %s %s\n", typ, 0, "-", displayPath)
				}
			} else {
				fmt.Println(displayPath)
			}
		}
		return nil
	}
	if isAz(target) {
		// Wildcard support for Azure paths
		var pattern string
		var parentPath string
		if strings.Contains(target, "*") {
			// Split at last slash before the wildcard
			lastSlash := strings.LastIndex(target, "/")
			if lastSlash >= 0 {
				parentPath = target[:lastSlash+1]
				pattern = target[lastSlash+1:]
			} else {
				parentPath = target
				pattern = "*"
			}
		} else {
			parentPath = target
		}
		ap, err := azblob.Parse(parentPath)
		if err != nil {
			return err
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
			// Wildcard filtering
			if pattern != "" {
				matched, _ := path.Match(pattern, strings.TrimSuffix(name, "/"))
				if !matched {
					continue
				}
			}
			var fullpath string
			if ap.Container == "" {
				fullpath = fmt.Sprintf("az://%s/%s", ap.Account, strings.TrimSuffix(name, "/"))
			} else if ap.Blob == "" {
				fullpath = fmt.Sprintf("az://%s/%s/%s", ap.Account, ap.Container, strings.TrimSuffix(name, "/"))
			} else {
				fullpath = fmt.Sprintf("az://%s/%s/%s", ap.Account, ap.Container, path.Join(ap.Blob, name))
				fullpath = strings.TrimSuffix(fullpath, "/")
			}
			displayPath := fullpath
			if relFlag {
				displayPath = strings.TrimSuffix(name, "/")
			}
			if long {
				typ := "-"
				if strings.HasSuffix(name, "/") || (bm.Size == 0 && strings.HasSuffix(ap.Blob, "/")) || ap.Container == "" {
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

	if isHF(root) {
		parentPath, pattern := hfSplitWildcard(root)
		hp, err := hf.Parse(parentPath)
		if err != nil {
			return err
		}
		hp.File = normalizeHFPrefix(hp.File)
		files, err := hf.ListFiles(ctx, hf.Path{Repo: hp.Repo})
		if err != nil {
			return err
		}
		list := hfFilterFiles(files, hp.File)
		sort.Strings(list)
		var count int64
		for _, name := range list {
			if name == "" {
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
			fullFile := path.Join(hp.File, name)
			fullpath := hf.Path{Repo: hp.Repo, File: fullFile}.String()
			display := fullpath
			if relFlag {
				display = name
			}
			if longFlag {
				if machine {
					fmt.Printf("f\t%d\t-\t%s\n", 0, display)
				} else {
					fmt.Printf("%10d  -  %s\n", 0, display)
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
	if isAz(root) {
		// Wildcard support for Azure paths
		var pattern string
		if strings.Contains(root, "*") {
			starIdx := strings.Index(root, "*")
			pattern = root[starIdx:]
			root = root[:starIdx]
		}
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
			if name == "" || strings.HasSuffix(name, "/") {
				continue
			}
			// Wildcard filtering: match only last segment
			if pattern != "" {
				last := name
				if idx := strings.LastIndex(name, "/"); idx >= 0 {
					last = name[idx+1:]
				}
				matched, _ := path.Match(pattern, last)
				if !matched {
					continue
				}
			}
			count++
			fullpath := ap.Child(name).String()
			display := fullpath
			if relFlag && prefix != "" && strings.HasPrefix(name, prefix) {
				display = strings.TrimPrefix(name, prefix)
			}
			if longFlag {
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

var outputMu sync.Mutex

func lockedPrintf(format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Printf(format, args...)
}

func lockedPrintln(args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Println(args...)
}

func lockedFprintf(w io.Writer, format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Fprintf(w, format, args...)
}

func runWorkerPool(ctx context.Context, concurrency int, ops []func() error) error {
	if len(ops) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(ops) {
		concurrency = len(ops)
	}
	var collected []error
	if concurrency == 1 {
		for _, op := range ops {
			if err := ctx.Err(); err != nil {
				collected = append(collected, err)
				break
			}
			if err := op(); err != nil {
				collected = append(collected, err)
			}
		}
		if len(collected) == 0 {
			return nil
		}
		if len(collected) == 1 {
			return collected[0]
		}
		return errors.Join(collected...)
	}
	work := make(chan func() error, len(ops))
	for _, op := range ops {
		work <- op
	}
	close(work)
	errs := make(chan error, len(ops))
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case op, ok := <-work:
					if !ok {
						return
					}
					if err := op(); err != nil {
						errs <- err
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			collected = append(collected, err)
		}
	}
	if err := ctx.Err(); err != nil {
		collected = append(collected, err)
	}
	if len(collected) == 0 {
		return nil
	}
	if len(collected) == 1 {
		return collected[0]
	}
	return errors.Join(collected...)
}

func cmdCP(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCP called", "args", c.Args().Slice())
	if c.Args().Len() < 2 {
		return fmt.Errorf("cp: need srcs dst")
	}
	overwrite := c.Bool("f")
	quiet := c.Bool("q") || c.Bool("quiet")
	concurrency := c.Int("concurrency")
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
	dirOps := make([]func() error, 0, len(srcs))
	fileOps := make([]func() error, 0, len(srcs))
	for _, src := range srcs {
		src := src
		srcAz := isAz(src)
		srcHF := isHF(src)
		base := filepath.Base(src)
		var srcAzPath azblob.AzurePath
		if srcAz {
			var err error
			srcAzPath, err = azblob.Parse(src)
			if err != nil {
				return err
			}
		}
		if srcHF {
			hfPath, err := hf.Parse(src)
			if err != nil {
				return err
			}
			if hfPath.File == "" {
				dirOps = append(dirOps, func() error { return copyHFDir(ctx, hfPath, dst, dstAz, overwrite, quiet, concurrency) })
				continue
			}
			base = hfPath.DefaultFilename()
			fileOps = append(fileOps, func() error { return copyHFFile(ctx, hfPath, base, dst, dstAz, overwrite, quiet, isDstDir) })
			continue
		}
		if srcAz {
			if srcAzPath.IsDirLike() {
				dirOps = append(dirOps, func() error { return copyTree(ctx, src, dst, overwrite, quiet, "cp", concurrency) })
				continue
			}
		} else if info, err := os.Stat(src); err == nil && info.IsDir() {
			dirOps = append(dirOps, func() error { return copyTree(ctx, src, dst, overwrite, quiet, "cp", concurrency) })
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
		fileOps = append(fileOps, func() error {
			if srcAz && dstAz {
				dap, _ := azblob.Parse(dstPath)
				reader, err := azblob.DownloadStream(ctx, srcAzPath)
				if err != nil {
					return err
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
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", src, dstPath)
				}
			} else if srcAz && !dstAz {
				reader, err := azblob.DownloadStream(ctx, srcAzPath)
				if err != nil {
					return err
				}
				if !overwrite {
					if _, err := os.Stat(dstPath); err == nil {
						reader.Close()
						return errors.New("cp: destination exists")
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return writeStreamToFile(dstPath, r, 0o644)
				}); err != nil {
					return err
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", src, dstPath)
				}
			} else if !srcAz && dstAz {
				dap, _ := azblob.Parse(dstPath)
				reader, err := os.Open(src)
				if err != nil {
					return err
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
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", src, dstPath)
				}
			} else {
				if err := fsops.CopyFile(src, dstPath, overwrite); err != nil {
					return fmt.Errorf("cp: %w", err)
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", src, dstPath)
				}
			}
			return nil
		})
	}
	for _, op := range dirOps {
		if err := op(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := runWorkerPool(ctx, concurrency, fileOps); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return nil
}

func copyTree(ctx context.Context, src, dst string, overwrite, quiet bool, errPrefix string, concurrency int) error {
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
			ops := make([]func() error, 0, len(list))
			for _, bm := range list {
				bm := bm
				ops = append(ops, func() error {
					reader, err := azblob.DownloadStream(ctx, sap.Child(bm.Name))
					if err != nil {
						lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, bm.Name, err)
						return err
					}
					if !overwrite {
						if _, err := azblob.HeadBlob(ctx, dap.Child(bm.Name)); err == nil {
							reader.Close()
							return nil
						}
					}
					if err := withReadCloser(reader, func(r io.Reader) error {
						return azblob.UploadStream(ctx, dap.Child(bm.Name), r)
					}); err != nil {
						lockedFprintf(os.Stderr, "%s: upload %s: %v\n", errPrefix, bm.Name, err)
						return err
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", sap.Child(bm.Name).String(), dap.Child(bm.Name).String())
					}
					return nil
				})
			}
			if err := runWorkerPool(ctx, concurrency, ops); err != nil {
				return err
			}
			return nil
		}
		if srcAz && !dstAz { // Azure -> local
			sap, _ := azblob.Parse(src)
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				return err
			}
			ops := make([]func() error, 0, len(list))
			for _, bm := range list {
				bm := bm
				ops = append(ops, func() error {
					reader, err := azblob.DownloadStream(ctx, sap.Child(bm.Name))
					if err != nil {
						lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, bm.Name, err)
						return err
					}
					outPath := filepath.Join(dst, bm.Name)
					if !overwrite {
						if _, err := os.Stat(outPath); err == nil {
							reader.Close()
							return nil
						}
					}
					if err := withReadCloser(reader, func(r io.Reader) error {
						return writeStreamToFile(outPath, r, 0o644)
					}); err != nil {
						lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, bm.Name, err)
						return err
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", sap.Child(bm.Name).String(), outPath)
					}
					return nil
				})
			}
			if err := runWorkerPool(ctx, concurrency, ops); err != nil {
				return err
			}
			return nil
		}
		if !srcAz && dstAz { // local -> Azure
			dap, _ := azblob.Parse(dst)
			// walk local
			var files []string
			var walkErrors bool
			if err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, p, err)
					walkErrors = true
					return nil
				}
				if d.IsDir() {
					return nil
				}
				files = append(files, p)
				return nil
			}); err != nil {
				return err
			}
			ops := make([]func() error, 0, len(files))
			for _, p := range files {
				p := p
				ops = append(ops, func() error {
					rel, _ := filepath.Rel(src, p)
					reader, err := os.Open(p)
					if err != nil {
						lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, rel, err)
						return err
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
						lockedFprintf(os.Stderr, "%s: upload %s: %v\n", errPrefix, rel, err)
						return err
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", p, dap.Child(rel).String())
					}
					return nil
				})
			}
			var walkErr error
			if walkErrors {
				walkErr = fmt.Errorf("%s: one or more files failed to copy", errPrefix)
			}
			if err := runWorkerPool(ctx, concurrency, ops); err != nil {
				return errors.Join(err, walkErr)
			}
			return walkErr
		}
	}
	var files []string
	var dirs []string
	if err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			dirs = append(dirs, rel)
			return nil
		}
		files = append(files, p)
		return nil
	}); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(dst, dir), 0o755); err != nil {
			return err
		}
	}
	ops := make([]func() error, 0, len(files))
	for _, p := range files {
		p := p
		ops = append(ops, func() error {
			rel, _ := filepath.Rel(src, p)
			return fsops.CopyFile(p, filepath.Join(dst, rel), overwrite)
		})
	}
	if err := runWorkerPool(ctx, concurrency, ops); err != nil {
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
		lockedPrintf("Copied %s -> %s\n", hfPath.String(), dstPath)
	}
	return nil
}

func copyHFDir(ctx context.Context, hfPath hf.Path, dst string, dstAz, overwrite, quiet bool, concurrency int) error {
	files, err := hf.ListFiles(ctx, hfPath)
	if err != nil {
		return err
	}
	ops := make([]func() error, 0, len(files))
	for _, file := range files {
		file := file
		ops = append(ops, func() error {
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
						return nil
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
						return nil
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return writeStreamToFile(dstPath, r, 0o644)
				}); err != nil {
					return err
				}
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", filePath.String(), dstPath)
			}
			return nil
		})
	}
	return runWorkerPool(ctx, concurrency, ops)
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
	concurrency := c.Int("concurrency")
	if c.Args().Len() == 0 {
		return fmt.Errorf("rm: need at least one path")
	}
	paths := make([]string, 0, c.Args().Len())
	for i := 0; i < c.Args().Len(); i++ {
		paths = append(paths, c.Args().Get(i))
	}
	ops := make([]func() error, 0, len(paths))
	for _, p := range paths {
		p := p
		ops = append(ops, func() error {
			if isAz(p) {
				ap, err := azblob.Parse(p)
				if err != nil {
					if force {
						return nil
					}
					return err
				}
				if err := azblob.Delete(ctx, ap); err != nil {
					if force && strings.Contains(strings.ToLower(err.Error()), "notfound") {
						return nil
					}
					return err
				}
				if !quiet {
					lockedPrintf("Deleted %s\n", p)
				}
			} else {
				if err := os.Remove(p); err != nil {
					if force && os.IsNotExist(err) {
						return nil
					}
					return err
				}
				if !quiet {
					lockedPrintf("Deleted %s\n", p)
				}
			}
			return nil
		})
	}
	return runWorkerPool(ctx, concurrency, ops)
}

func cmdRMTree(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdRMTree called", "args", c.Args().Slice())
	quiet := c.Bool("q") || c.Bool("quiet")
	concurrency := c.Int("concurrency")
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
		ops := make([]func() error, 0, len(list))
		for _, bm := range list {
			if bm.Name == "" || strings.HasSuffix(bm.Name, "/") {
				continue
			}
			bm := bm
			ops = append(ops, func() error {
				if err := azblob.Delete(ctx, ap.Child(bm.Name)); err != nil {
					lockedFprintf(os.Stderr, "rmtree: %s: %v\n", bm.Name, err)
					return err
				}
				if !quiet {
					lockedPrintf("Deleted %s\n", ap.Child(bm.Name).String())
				}
				return nil
			})
		}
		if err := runWorkerPool(ctx, concurrency, ops); err != nil {
			return err
		}
		return nil
	}
	err := os.RemoveAll(root)
	if err == nil && !quiet {
		lockedPrintf("Deleted %s\n", root)
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
	concurrency := c.Int("concurrency")
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
		var sap azblob.AzurePath
		var dap azblob.AzurePath
		if srcAz {
			sap, _ = azblob.Parse(src)
		}
		if dstAz {
			var err error
			dap, err = azblob.Parse(dst)
			if err != nil {
				fmt.Fprintf(os.Stderr, "sync: %s: %v\n", dst, err)
				return err
			}
		}
		ops := make([]func() error, 0, len(files))
		for _, f := range files {
			f := f
			ops = append(ops, func() error {
				sPath := f.rel
				if srcAz && dstAz {
					reader, err := azblob.DownloadStream(ctx, sap.Child(sPath))
					if err != nil {
						lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
						return fmt.Errorf("sync: %s: %w", sPath, err)
					}
					if dry {
						if !quiet {
							lockedPrintln("COPY", sap.Child(sPath).String(), "->", dap.Child(sPath).String())
						}
						reader.Close()
						return nil
					}
					if err := withReadCloser(reader, func(r io.Reader) error {
						return azblob.UploadStream(ctx, dap.Child(sPath), r)
					}); err != nil {
						lockedFprintf(os.Stderr, "sync upload: %s: %v\n", sPath, err)
						return fmt.Errorf("sync upload: %s: %w", sPath, err)
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", sap.Child(sPath).String(), dap.Child(sPath).String())
					}
					return nil
				}
				if srcHF && dstAz {
					hfFile := hf.Path{Repo: hfPath.Repo, File: sPath}
					if dry {
						if !quiet {
							lockedPrintln("COPY", hfFile.String(), "->", dap.Child(sPath).String())
						}
						return nil
					}
					data, err := hf.Download(ctx, hfFile)
					if err != nil {
						lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
						return fmt.Errorf("sync: %s: %w", sPath, err)
					}
					if err := azblob.Upload(ctx, dap.Child(sPath), data); err != nil {
						lockedFprintf(os.Stderr, "sync upload: %s: %v\n", sPath, err)
						return fmt.Errorf("sync upload: %s: %w", sPath, err)
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", hfFile.String(), dap.Child(sPath).String())
					}
					return nil
				}
				if srcAz && !dstAz {
					reader, err := azblob.DownloadStream(ctx, sap.Child(sPath))
					if err != nil {
						lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
						return fmt.Errorf("sync: %s: %w", sPath, err)
					}
					out := filepath.Join(dst, sPath)
					if dry {
						if !quiet {
							lockedPrintln("COPY", sap.Child(sPath).String(), "->", out)
						}
						reader.Close()
						return nil
					}
					if err := withReadCloser(reader, func(r io.Reader) error {
						return writeStreamToFile(out, r, 0o644)
					}); err != nil {
						lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
						return fmt.Errorf("sync: %s: %w", sPath, err)
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", sap.Child(sPath).String(), out)
					}
					return nil
				}
				if !srcAz && dstAz {
					reader, err := os.Open(filepath.Join(src, sPath))
					if err != nil {
						lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
						return fmt.Errorf("sync: %s: %w", sPath, err)
					}
					if dry {
						if !quiet {
							lockedPrintln("COPY", filepath.Join(src, sPath), "->", dap.Child(sPath).String())
						}
						reader.Close()
						return nil
					}
					if err := withReadCloser(reader, func(r io.Reader) error {
						return azblob.UploadStream(ctx, dap.Child(sPath), r)
					}); err != nil {
						lockedFprintf(os.Stderr, "sync upload: %s: %v\n", sPath, err)
						return fmt.Errorf("sync upload: %s: %w", sPath, err)
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", filepath.Join(src, sPath), dap.Child(sPath).String())
					}
					return nil
				}
				return nil
			})
		}
		workerErr := runWorkerPool(ctx, concurrency, ops)
		if workerErr != nil {
			lockedFprintf(os.Stderr, "sync: one or more files failed\n")
		}
		// delete phase not implemented for cloud combos yet
		return workerErr
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
	ops := make([]func() error, 0, len(srcFiles))
	for _, r := range srcFiles {
		r := r
		ops = append(ops, func() error {
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
						lockedPrintln("COPY", sPath, "->", dPath)
					}
				} else {
					if err := fsops.CopyFile(sPath, dPath, true); err != nil {
						lockedFprintf(os.Stderr, "sync copy: %s: %v\n", r, err)
						return err
					}
					// preserve modtime
					if info, err := os.Stat(sPath); err == nil {
						os.Chtimes(dPath, info.ModTime(), info.ModTime())
					}
					if !quiet {
						lockedPrintf("Copied %s -> %s\n", sPath, dPath)
					}
				}
			}
			return nil
		})
	}
	workerErr := runWorkerPool(ctx, concurrency, ops)
	if workerErr != nil {
		lockedFprintf(os.Stderr, "sync: one or more files failed\n")
	}
	if del {
		var deleteFiles []string
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
				deleteFiles = append(deleteFiles, p)
			}
			return nil
		})
		ops := make([]func() error, 0, len(deleteFiles))
		for _, p := range deleteFiles {
			p := p
			ops = append(ops, func() error {
				if dry {
					if !quiet {
						lockedPrintln("DELETE", p)
					}
					return nil
				}
				os.Remove(p)
				if !quiet {
					lockedPrintf("Deleted %s\n", p)
				}
				return nil
			})
		}
		if err := runWorkerPool(ctx, concurrency, ops); err != nil {
			return errors.Join(workerErr, err)
		}
	}
	return workerErr
}

func cmdMD5Sum(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdMD5Sum called", "args", c.Args().Slice())
	if c.Args().Len() == 0 {
		return fmt.Errorf("md5sum: need at least one path")
	}
	for i := 0; i < c.Args().Len(); i++ {
		p := c.Args().Get(i)
		switch {
		case isAz(p):
			ap, err := azblob.Parse(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "md5sum: %s: %v\n", p, err)
				continue
			}
			reader, err := azblob.DownloadStream(ctx, ap)
			if err != nil {
				fmt.Fprintf(os.Stderr, "md5sum: %s: %v\n", p, err)
				continue
			}
			printMD5Sum(reader, p)
		case isHF(p):
			hfPath, err := hf.Parse(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "md5sum: %s: %v\n", p, err)
				continue
			}
			reader, err := hf.DownloadStream(ctx, hfPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "md5sum: %s: %v\n", p, err)
				continue
			}
			printMD5Sum(reader, p)
		default:
			f, err := os.Open(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "md5sum: %s: %v\n", p, err)
				continue
			}
			printMD5Sum(f, p)
		}
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
