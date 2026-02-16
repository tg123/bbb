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
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	return strings.HasPrefix(s, "az://") || azblob.IsBlobURL(s)
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
				UsageText: "bbb cp [-q|--quiet] [--concurrency N] [--retry-count N] srcs [srcs ...] dst",
				Aliases:   []string{"cpr", "cptree"},
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "force overwrite"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: runtime.NumCPU()},
					&cli.IntFlag{Name: "retry-count", Usage: "Retry operations on error", Value: 0},
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
				UsageText: "bbb rm [-q|--quiet] [--concurrency N] [--retry-count N] paths [paths ...]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "ignore nonexistent files"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: runtime.NumCPU()},
					&cli.IntFlag{Name: "retry-count", Usage: "Retry operations on error", Value: 0},
				},
				Action: cmdRM,
			},
			{
				Name:      "rmtree",
				Aliases:   []string{"rmr"},
				Usage:     "Remove directory tree",
				UsageText: "bbb rmtree [-q|--quiet] [--concurrency N] [--retry-count N] path",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: runtime.NumCPU()},
					&cli.IntFlag{Name: "retry-count", Usage: "Retry operations on error", Value: 0},
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
				UsageText: "bbb sync [-q|--quiet] [--delete] [-x EXCLUDE|--exclude EXCLUDE] [--concurrency N] [--retry-count N] src dst",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "dry-run", Usage: "show actions without applying"},
					&cli.BoolFlag{Name: "delete", Usage: "Delete destination files that don't exist in source"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: runtime.NumCPU()},
					&cli.IntFlag{Name: "retry-count", Usage: "Retry operations on error", Value: 0},
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
	list, err := bbbfs.ListRecursive(ctx, parentPath)
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
		if schemeIdx := strings.Index(target, "://"); schemeIdx >= 0 && schemeIdx < starIdx {
			pathStart := schemeIdx + len("://")
			if !strings.Contains(target[pathStart:starIdx], "/") {
				return target, "*"
			}
		}
		if lastSlash := strings.LastIndex(target[:starIdx], "/"); lastSlash >= 0 {
			return target[:lastSlash+1], target[lastSlash+1:]
		}
		return target, "*"
	}
	return target, ""
}

func cmdCat(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCat called", "args", c.Args().Slice())
	if c.Args().Len() == 0 {
		return fmt.Errorf("cat: need at least one file")
	}
	for i := 0; i < c.Args().Len(); i++ {
		p := c.Args().Get(i)
		reader, err := bbbfs.Resolve(p).Read(ctx, p)
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
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

type progressBar struct {
	label       string
	total       int64
	width       int
	done        atomic.Int64
	lastPercent atomic.Int64
	finished    atomic.Bool
}

func newProgressBar(total int, label string, quiet bool) *progressBar {
	if quiet || total <= 1 || !isTerminal(os.Stderr) {
		return nil
	}
	bar := &progressBar{
		label: label,
		total: int64(total),
		width: 28,
	}
	bar.render(0)
	return bar
}

func (p *progressBar) Increment() {
	if p == nil {
		return
	}
	done := p.done.Add(1)
	p.render(done)
}

func (p *progressBar) Finish() {
	if p == nil {
		return
	}
	p.done.Store(p.total)
	p.render(p.total)
}

func (p *progressBar) render(done int64) {
	if p == nil {
		return
	}
	if p.total <= 0 {
		return
	}
	if done < 0 {
		done = 0
	}
	if done > p.total {
		done = p.total
	}
	percent := done * 100 / p.total
	if done != p.total {
		for {
			prev := p.lastPercent.Load()
			if percent == prev {
				return
			}
			if p.lastPercent.CompareAndSwap(prev, percent) {
				break
			}
		}
	} else if !p.finished.CompareAndSwap(false, true) {
		return
	}
	line := formatProgressBar(p.label, done, p.total, p.width)
	lockedFprintf(os.Stderr, "\r%s", line)
	if done == p.total {
		lockedFprintf(os.Stderr, "\n")
	}
}

func formatProgressBar(label string, done, total int64, width int) string {
	if width < 1 {
		width = 1
	}
	if total < 1 {
		total = 1
	}
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	percent := done * 100 / total
	filled := int(done * int64(width) / total)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
	return fmt.Sprintf("%s [%s] %3d%% (%d/%d)", label, bar, percent, done, total)
}

func sendOp[T any](ctx context.Context, ch chan<- T, op T) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case ch <- op:
		return nil
	}
}

func runOpPool[T any](ctx context.Context, concurrency int, producer func(chan<- T) error, worker func(T) error) error {
	if concurrency < 1 {
		concurrency = 1
	}
	pending := make(chan T, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var collected []error
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for op := range pending {
				// Process received ops even if ctx is canceled to avoid dropping queued work.
				// Producers stop sending new work when context is canceled, so workers drain
				// the bounded channel before checking cancellation.
				if err := worker(op); err != nil {
					mu.Lock()
					collected = append(collected, err)
					mu.Unlock()
				}
				if ctx.Err() != nil {
					return
				}
			}
		}()
	}
	produceErr := func() error {
		defer close(pending)
		return producer(pending)
	}()
	wg.Wait()
	if produceErr != nil {
		collected = append(collected, produceErr)
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

func retryOp(ctx context.Context, retryCount int, op func() error) error {
	if retryCount < 0 {
		retryCount = 0
	}
	var err error
	for attempt := 0; attempt <= retryCount; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err = op()
		if err == nil {
			return nil
		}
	}
	return err
}

func runOpPoolWithRetry[T any](ctx context.Context, concurrency int, retryCount int, producer func(chan<- T) error, worker func(T) error) error {
	return runOpPool(ctx, concurrency, producer, func(op T) error {
		return retryOp(ctx, retryCount, func() error {
			return worker(op)
		})
	})
}

func runOpPoolWithRetryProgress[T any](ctx context.Context, concurrency int, retryCount int, total int, quiet bool, label string, producer func(chan<- T) error, worker func(T) error) error {
	progress := newProgressBar(total, label, quiet)
	err := runOpPoolWithRetry(ctx, concurrency, retryCount, producer, func(op T) error {
		err := worker(op)
		if progress != nil {
			progress.Increment()
		}
		return err
	})
	if progress != nil {
		progress.Finish()
	}
	return err
}

func cmdCP(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCP called", "args", c.Args().Slice())
	if c.Args().Len() < 2 {
		return fmt.Errorf("cp: need srcs dst")
	}
	overwrite := c.Bool("f")
	quiet := c.Bool("q") || c.Bool("quiet")
	concurrency := c.Int("concurrency")
	retryCount := c.Int("retry-count")
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
	type cpDirOp struct {
		src   string
		dst   string
		srcHF bool
		hf    hf.Path
	}
	type cpFileOp struct {
		src       string
		dst       string
		srcAz     bool
		dstAz     bool
		srcHF     bool
		srcAzPath azblob.AzurePath
		hf        hf.Path
		base      string
	}
	dirOps := make([]cpDirOp, 0, len(srcs))
	fileOps := make([]cpFileOp, 0, len(srcs))
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
				dirOps = append(dirOps, cpDirOp{src: src, dst: dst, srcHF: true, hf: hfPath})
				continue
			}
			base = hfPath.DefaultFilename()
			fileOps = append(fileOps, cpFileOp{
				src:   src,
				dst:   dst,
				dstAz: dstAz,
				srcHF: true,
				hf:    hfPath,
				base:  base,
			})
			continue
		}
		if srcAz {
			if srcAzPath.IsDirLike() {
				dirOps = append(dirOps, cpDirOp{src: src, dst: dst})
				continue
			}
		} else if info, err := os.Stat(src); err == nil && info.IsDir() {
			dirOps = append(dirOps, cpDirOp{src: src, dst: dst})
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
		fileOps = append(fileOps, cpFileOp{
			src:       src,
			dst:       dstPath,
			srcAz:     srcAz,
			dstAz:     dstAz,
			srcAzPath: srcAzPath,
		})
	}
	for _, op := range dirOps {
		var err error
		if op.srcHF {
			err = copyHFDir(ctx, op.hf, op.dst, dstAz, overwrite, quiet, concurrency, retryCount)
		} else {
			err = copyTree(ctx, op.src, op.dst, overwrite, quiet, "cp", concurrency, retryCount)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(fileOps), quiet, "cp", func(pending chan<- cpFileOp) error {
		for _, op := range fileOps {
			if err := sendOp(ctx, pending, op); err != nil {
				return err
			}
		}
		return nil
	}, func(op cpFileOp) error {
		if op.srcHF {
			return copyHFFile(ctx, op.hf, op.base, op.dst, op.dstAz, overwrite, quiet, isDstDir)
		}
		if op.srcAz && op.dstAz {
			dap, _ := azblob.Parse(op.dst)
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					return errors.New("cp: destination exists")
				}
			}
			if err := azblob.CopyBlobServerSide(ctx, op.srcAzPath, dap); err != nil {
				return err
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
			}
			return nil
		}
		if op.srcAz && !op.dstAz {
			reader, err := azblob.DownloadStream(ctx, op.srcAzPath)
			if err != nil {
				return err
			}
			if !overwrite {
				if _, err := os.Stat(op.dst); err == nil {
					if cerr := reader.Close(); cerr != nil {
						return cerr
					}
					return errors.New("cp: destination exists")
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return writeStreamToFile(op.dst, r, 0o644)
			}); err != nil {
				return err
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
			}
			return nil
		}
		if !op.srcAz && op.dstAz {
			dap, _ := azblob.Parse(op.dst)
			reader, err := os.Open(op.src)
			if err != nil {
				return err
			}
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					if cerr := reader.Close(); cerr != nil {
						return cerr
					}
					return errors.New("cp: destination exists")
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return azblob.UploadStream(ctx, dap, r)
			}); err != nil {
				return err
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
			}
			return nil
		}
		if err := fsops.CopyFile(op.src, op.dst, overwrite); err != nil {
			return fmt.Errorf("cp: %w", err)
		}
		if !quiet {
			lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
		}
		return nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return nil
}

func copyTree(ctx context.Context, src, dst string, overwrite, quiet bool, errPrefix string, concurrency int, retryCount int) error {
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
			type azToAzOp struct {
				name string
			}
			return runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(list), quiet, errPrefix, func(pending chan<- azToAzOp) error {
				for _, bm := range list {
					if err := sendOp(ctx, pending, azToAzOp{name: bm.Name}); err != nil {
						return err
					}
				}
				return nil
			}, func(work azToAzOp) error {
				reader, err := azblob.DownloadStream(ctx, sap.Child(work.name))
				if err != nil {
					lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, work.name, err)
					return err
				}
				if !overwrite {
					if _, err := azblob.HeadBlob(ctx, dap.Child(work.name)); err == nil {
						if cerr := reader.Close(); cerr != nil {
							return cerr
						}
						return nil
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return azblob.UploadStream(ctx, dap.Child(work.name), r)
				}); err != nil {
					lockedFprintf(os.Stderr, "%s: upload %s: %v\n", errPrefix, work.name, err)
					return err
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", sap.Child(work.name).String(), dap.Child(work.name).String())
				}
				return nil
			})
		}
		if srcAz && !dstAz { // Azure -> local
			sap, _ := azblob.Parse(src)
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				return err
			}
			type azToLocalOp struct {
				name string
			}
			return runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(list), quiet, errPrefix, func(pending chan<- azToLocalOp) error {
				for _, bm := range list {
					if err := sendOp(ctx, pending, azToLocalOp{name: bm.Name}); err != nil {
						return err
					}
				}
				return nil
			}, func(work azToLocalOp) error {
				reader, err := azblob.DownloadStream(ctx, sap.Child(work.name))
				if err != nil {
					lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, work.name, err)
					return err
				}
				outPath := filepath.Join(dst, work.name)
				if !overwrite {
					if _, err := os.Stat(outPath); err == nil {
						if cerr := reader.Close(); cerr != nil {
							return cerr
						}
						return nil
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return writeStreamToFile(outPath, r, 0o644)
				}); err != nil {
					lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, work.name, err)
					return err
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", sap.Child(work.name).String(), outPath)
				}
				return nil
			})
		}
		if !srcAz && dstAz { // local -> Azure
			dap, _ := azblob.Parse(dst)
			// walk local
			type localToAzOp struct {
				rel string
			}
			var walkIssues bool
			ops := make([]localToAzOp, 0)
			walkErr := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
				if err != nil {
					lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, p, err)
					walkIssues = true
					return nil
				}
				if d.IsDir() {
					return nil
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				rel, _ := filepath.Rel(src, p)
				ops = append(ops, localToAzOp{rel: rel})
				return nil
			})
			if walkErr != nil {
				return walkErr
			}
			var walkIssueErr error
			if walkIssues {
				walkIssueErr = fmt.Errorf("%s: one or more files failed to copy", errPrefix)
			}
			err := runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(ops), quiet, errPrefix, func(pending chan<- localToAzOp) error {
				for _, op := range ops {
					if err := sendOp(ctx, pending, op); err != nil {
						return err
					}
				}
				return nil
			}, func(work localToAzOp) error {
				p := filepath.Join(src, work.rel)
				reader, err := os.Open(p)
				if err != nil {
					lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, work.rel, err)
					return err
				}
				if !overwrite {
					if _, err := azblob.HeadBlob(ctx, dap.Child(work.rel)); err == nil {
						if cerr := reader.Close(); cerr != nil {
							return cerr
						}
						return nil
					}
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return azblob.UploadStream(ctx, dap.Child(work.rel), r)
				}); err != nil {
					lockedFprintf(os.Stderr, "%s: upload %s: %v\n", errPrefix, work.rel, err)
					return err
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", p, dap.Child(work.rel).String())
				}
				return nil
			})
			if walkIssueErr != nil {
				return errors.Join(err, walkIssueErr)
			}
			return err
		}
	}
	type copyOp struct {
		src   string
		dst   string
		isDir bool
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	ops := make([]copyOp, 0)
	if err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			ops = append(ops, copyOp{dst: filepath.Join(dst, rel), isDir: true})
			return nil
		}
		ops = append(ops, copyOp{src: p, dst: filepath.Join(dst, rel)})
		return nil
	}); err != nil {
		return err
	}
	return runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(ops), quiet, errPrefix, func(pending chan<- copyOp) error {
		for _, op := range ops {
			if err := sendOp(ctx, pending, op); err != nil {
				return err
			}
		}
		return nil
	}, func(work copyOp) error {
		if work.isDir {
			// Directory ops only carry dst; src is not used for these operations.
			return os.MkdirAll(work.dst, 0o755)
		}
		if work.src == "" {
			return errors.New("copytree: missing source path")
		}
		return fsops.CopyFile(work.src, work.dst, overwrite)
	})
}

func copyHFFile(ctx context.Context, hfPath hf.Path, base, dst string, dstAz, overwrite, quiet, dstDir bool) error {
	dstPath, err := resolveDstPath(dst, dstAz, base, dstDir)
	if err != nil {
		return err
	}
	if !overwrite {
		if dstAz {
			dap, err := azblob.Parse(dstPath)
			if err != nil {
				return err
			}
			if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
				return errors.New("cp: destination must be a blob path")
			}
			if _, err := azblob.HeadBlob(ctx, dap); err == nil {
				return errors.New("cp: destination exists")
			}
		} else if _, err := os.Stat(dstPath); err == nil {
			return errors.New("cp: destination exists")
		}
	}
	reader, err := bbbfs.Resolve(hfPath.String()).Read(ctx, hfPath.String())
	if err != nil {
		return err
	}
	if err := withReadCloser(reader, func(r io.Reader) error {
		return bbbfs.Resolve(dstPath).Write(ctx, dstPath, r)
	}); err != nil {
		return err
	}
	if !quiet {
		lockedPrintf("Copied %s -> %s\n", hfPath.String(), dstPath)
	}
	return nil
}

func copyHFDir(ctx context.Context, hfPath hf.Path, dst string, dstAz, overwrite, quiet bool, concurrency int, retryCount int) error {
	files, err := hf.ListFiles(ctx, hfPath)
	if err != nil {
		return err
	}
	type hfOp struct {
		file string
	}
	return runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(files), quiet, "cp", func(pending chan<- hfOp) error {
		for _, file := range files {
			if err := sendOp(ctx, pending, hfOp{file: file}); err != nil {
				return err
			}
		}
		return nil
	}, func(op hfOp) error {
		filePath := hf.Path{Repo: hfPath.Repo, File: op.file}
		dstPath, err := resolveDstPath(dst, dstAz, op.file, true)
		if err != nil {
			return err
		}
		if !overwrite {
			if dstAz {
				dap, err := azblob.Parse(dstPath)
				if err != nil {
					return err
				}
				if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
					return errors.New("cp: destination must be a blob path")
				}
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					return nil
				}
			} else if _, err := os.Stat(dstPath); err == nil {
				return nil
			}
		}
		reader, err := bbbfs.Resolve(filePath.String()).Read(ctx, filePath.String())
		if err != nil {
			return err
		}
		if err := withReadCloser(reader, func(r io.Reader) error {
			return bbbfs.Resolve(dstPath).Write(ctx, dstPath, r)
		}); err != nil {
			return err
		}
		if !quiet {
			lockedPrintf("Copied %s -> %s\n", filePath.String(), dstPath)
		}
		return nil
	})
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
	defer func() {
		_ = reader.Close()
	}()
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
			if cerr := f.Close(); cerr != nil {
				fmt.Fprintln(os.Stderr, cerr)
				os.Exit(1)
			}
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
	retryCount := c.Int("retry-count")
	if c.Args().Len() == 0 {
		return fmt.Errorf("rm: need at least one path")
	}
	paths := make([]string, 0, c.Args().Len())
	for i := 0; i < c.Args().Len(); i++ {
		paths = append(paths, c.Args().Get(i))
	}
	type rmOp struct {
		path string
	}
	return runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(paths), quiet, "rm", func(pending chan<- rmOp) error {
		for _, p := range paths {
			if err := sendOp(ctx, pending, rmOp{path: p}); err != nil {
				return err
			}
		}
		return nil
	}, func(op rmOp) error {
		if isAz(op.path) {
			ap, err := azblob.Parse(op.path)
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
				lockedPrintf("Deleted %s\n", op.path)
			}
		} else {
			if err := os.Remove(op.path); err != nil {
				if force && os.IsNotExist(err) {
					return nil
				}
				return err
			}
			if !quiet {
				lockedPrintf("Deleted %s\n", op.path)
			}
		}
		return nil
	})
}

func cmdRMTree(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdRMTree called", "args", c.Args().Slice())
	quiet := c.Bool("q") || c.Bool("quiet")
	concurrency := c.Int("concurrency")
	retryCount := c.Int("retry-count")
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
		type rmTreeOp struct {
			name string
		}
		ops := make([]rmTreeOp, 0, len(list))
		for _, bm := range list {
			if bm.Name == "" || strings.HasSuffix(bm.Name, "/") {
				continue
			}
			ops = append(ops, rmTreeOp{name: bm.Name})
		}
		return runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(ops), quiet, "rmtree", func(pending chan<- rmTreeOp) error {
			for _, op := range ops {
				if err := sendOp(ctx, pending, op); err != nil {
					return err
				}
			}
			return nil
		}, func(op rmTreeOp) error {
			if err := azblob.Delete(ctx, ap.Child(op.name)); err != nil {
				lockedFprintf(os.Stderr, "rmtree: %s: %v\n", op.name, err)
				return err
			}
			if !quiet {
				lockedPrintf("Deleted %s\n", ap.Child(op.name).String())
			}
			return nil
		})
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
	return syncHFFilesFromList(files, excludeMatch), nil
}

func syncHFFilesFromList(files []string, excludeMatch func(string) bool) []string {
	out := make([]string, 0, len(files))
	for _, file := range files {
		if excludeMatch(file) {
			continue
		}
		out = append(out, file)
	}
	return out
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
	retryCount := c.Int("retry-count")
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
			if err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
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
			}); err != nil {
				return err
			}
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
		workerErr := runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(files), quiet, "sync", func(pending chan<- item) error {
			for _, f := range files {
				if err := sendOp(ctx, pending, f); err != nil {
					return err
				}
			}
			return nil
		}, func(f item) error {
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
					if cerr := reader.Close(); cerr != nil {
						return cerr
					}
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
				reader, err := hf.DownloadStream(ctx, hfFile)
				if err != nil {
					lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					return fmt.Errorf("sync: %s: %w", sPath, err)
				}
				if err := withReadCloser(reader, func(r io.Reader) error {
					return azblob.UploadStream(ctx, dap.Child(sPath), r)
				}); err != nil {
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
					if cerr := reader.Close(); cerr != nil {
						return cerr
					}
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
					if cerr := reader.Close(); cerr != nil {
						return cerr
					}
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
		// delete phase not implemented for cloud combos yet
		return workerErr
	}
	// collect source files
	type syncOp struct {
		rel string
	}
	// build set for deletion check
	var srcSet map[string]struct{}
	if del {
		srcSet = make(map[string]struct{})
	}
	// copy/update
	syncOps := make([]syncOp, 0)
	if err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
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
		if srcSet != nil {
			srcSet[rel] = struct{}{}
		}
		syncOps = append(syncOps, syncOp{rel: rel})
		return nil
	}); err != nil {
		return err
	}
	workerErr := runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(syncOps), quiet, "sync", func(pending chan<- syncOp) error {
		for _, op := range syncOps {
			if err := sendOp(ctx, pending, op); err != nil {
				return err
			}
		}
		return nil
	}, func(op syncOp) error {
		sPath := filepath.Join(src, op.rel)
		dPath := filepath.Join(dst, op.rel)
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
					lockedFprintf(os.Stderr, "sync copy: %s: %v\n", op.rel, err)
					return err
				}
				// preserve modtime
				if info, err := os.Stat(sPath); err == nil {
					if err := os.Chtimes(dPath, info.ModTime(), info.ModTime()); err != nil {
						return err
					}
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", sPath, dPath)
				}
			}
		}
		return nil
	})
	if del {
		type deleteOp struct {
			path string
		}
		deleteOps := make([]deleteOp, 0)
		if err := filepath.WalkDir(dst, func(p string, d os.DirEntry, err error) error {
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
				deleteOps = append(deleteOps, deleteOp{path: p})
			}
			return nil
		}); err != nil {
			return errors.Join(workerErr, err)
		}
		if err := runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(deleteOps), quiet, "sync delete", func(pending chan<- deleteOp) error {
			for _, op := range deleteOps {
				if err := sendOp(ctx, pending, op); err != nil {
					return err
				}
			}
			return nil
		}, func(op deleteOp) error {
			if dry {
				if !quiet {
					lockedPrintln("DELETE", op.path)
				}
				return nil
			}
			if err := os.Remove(op.path); err != nil && !os.IsNotExist(err) {
				return err
			}
			if !quiet {
				lockedPrintf("Deleted %s\n", op.path)
			}
			return nil
		}); err != nil {
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
	defer func() {
		_ = r.Close()
	}()
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
