package main

import (
	"bufio"
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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

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
				UsageText: "bbb cp [-q|--quiet] [--concurrency N] [--retry-count N] [--taskfile FILE|--taskfile -] [--taskfile-state FILE]\n   or: bbb cp [-q|--quiet] [--concurrency N] [--retry-count N] srcs [srcs ...] dst",
				Aliases:   []string{"cpr", "cptree"},
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f", Usage: "force overwrite"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: runtime.NumCPU()},
					&cli.IntFlag{Name: "retry-count", Usage: "Retry operations on error", Value: 0},
					&cli.StringFlag{Name: "taskfile", Usage: "Task file containing one `src dst` pair per line (`-` for stdin)"},
					&cli.StringFlag{Name: "taskfile-state", Usage: "State file for `cp --taskfile` crash recovery"},
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
				UsageText: "bbb sync [-q|--quiet] [--delete] [-x EXCLUDE|--exclude EXCLUDE] [--concurrency N] [--retry-count N] [--taskfile FILE|--taskfile -] src dst",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "dry-run", Usage: "show actions without applying"},
					&cli.BoolFlag{Name: "delete", Usage: "Delete destination files that don't exist in source"},
					&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: runtime.NumCPU()},
					&cli.IntFlag{Name: "retry-count", Usage: "Retry operations on error", Value: 0},
					&cli.StringFlag{Name: "x", Aliases: []string{"exclude"}, Usage: "Exclude files matching this regex"},
					&cli.StringFlag{Name: "taskfile", Usage: "Task file containing one `src dst` pair per line (`-` for stdin)"},
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
	// If listing returns nothing and no wildcard was used, the target
	// may be a file rather than a directory. Fall back to Stat so that
	// single-file paths (e.g. az://account/container/blob) are shown.
	if len(entries) == 0 && pattern == "" {
		st, statErr := fs.Stat(ctx, parentPath)
		if statErr == nil && !st.IsDir {
			entries = []bbbfs.Entry{st}
		}
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
	var list []bbbfs.Entry
	for result := range bbbfs.ListRecursive(ctx, parentPath) {
		if result.Err != nil {
			return result.Err
		}
		list = append(list, result.Entry)
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
	metaIdx := strings.IndexAny(target, "*?[")
	if metaIdx < 0 {
		return target, ""
	}
	if schemeIdx := strings.Index(target, "://"); schemeIdx >= 0 && schemeIdx < metaIdx {
		pathStart := schemeIdx + len("://")
		if !strings.Contains(target[pathStart:metaIdx], "/") {
			return target, "*"
		}
	}
	if lastSlash := strings.LastIndex(target[:metaIdx], "/"); lastSlash >= 0 {
		return target[:lastSlash+1], target[lastSlash+1:]
	}
	return target, "*"
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

var (
	outputMu     sync.Mutex
	activeBarPtr *progressBar // guarded by outputMu
)

func clearActiveBar() {
	if activeBarPtr != nil && isTerminal(os.Stderr) {
		fmt.Fprintf(os.Stderr, "\r"+ansiClear)
	}
}

func rerenderActiveBar() {
	if activeBarPtr != nil {
		activeBarPtr.renderUnlocked()
	}
}

func lockedPrintf(format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBar()
	fmt.Printf(format, args...)
	rerenderActiveBar()
}

func lockedPrintln(args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBar()
	fmt.Println(args...)
	rerenderActiveBar()
}

func lockedFprintf(w io.Writer, format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBar()
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	rerenderActiveBar()
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

type progressBar struct {
	label     string
	width     int
	showSpeed bool
	startedAt time.Time
	total     atomic.Int64
	done      atomic.Int64
	bytesDone atomic.Int64
	lastDone  atomic.Int64
	lastTotal atomic.Int64
	finished  atomic.Bool
}

const (
	progressUninitialized = int64(-1)
	minProgressTotal      = 2

	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiGreen = "\033[32m"
	ansiCyan  = "\033[36m"
	ansiGray  = "\033[90m"
	ansiClear = "\033[K"
)

func clampProgressTotal(total int64) int64 {
	if total < int64(minProgressTotal) {
		return int64(minProgressTotal)
	}
	return total
}

func newProgressBar(total int, label string, quiet bool, showSpeed bool) *progressBar {
	if quiet || total <= 1 || !isTerminal(os.Stderr) {
		return nil
	}
	bar := &progressBar{
		label:     label,
		width:     28,
		showSpeed: showSpeed,
		startedAt: time.Now(),
	}
	bar.total.Store(int64(total))
	bar.lastDone.Store(progressUninitialized)
	bar.lastTotal.Store(progressUninitialized)
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

func (p *progressBar) AddBytes(n int64) {
	if p == nil || n <= 0 {
		return
	}
	p.bytesDone.Add(n)
}

func (p *progressBar) SetTotal(total int64) {
	if p == nil {
		return
	}
	if total < 1 {
		total = 1
	}
	p.total.Store(total)
	if p.done.Load() < total {
		p.finished.Store(false)
	}
	p.render(p.done.Load())
}

func (p *progressBar) Finish() {
	if p == nil {
		return
	}
	if !p.finished.CompareAndSwap(false, true) {
		return
	}
	total := p.total.Load()
	if total < 1 {
		total = 1
	}
	p.done.Store(total)
	outputMu.Lock()
	defer outputMu.Unlock()
	p.renderUnlocked()
	fmt.Fprintf(os.Stderr, "\n")
	if activeBarPtr == p {
		activeBarPtr = nil
	}
}

// renderUnlocked writes the progress bar to stderr. outputMu must be held.
func (p *progressBar) renderUnlocked() {
	if p == nil {
		return
	}
	done := p.done.Load()
	total := p.total.Load()
	if total <= 0 {
		return
	}
	done, total = clampProgress(done, total)
	elapsed := time.Since(p.startedAt).Seconds()
	speed := 0.0
	if p.showSpeed && elapsed > 0 {
		speed = float64(p.bytesDone.Load()) / elapsed
	}
	if isTerminal(os.Stderr) {
		line := formatFancyBar(p.label, done, total, p.width, speed, p.showSpeed)
		fmt.Fprintf(os.Stderr, "\r"+ansiClear+"%s", line)
	} else {
		line := formatProgressBar(p.label, done, total, p.width, speed, p.showSpeed)
		fmt.Fprintf(os.Stderr, "\r%s", line)
	}
}

func clampProgress(done, total int64) (int64, int64) {
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	return done, total
}

func (p *progressBar) render(done int64) {
	if p == nil {
		return
	}
	total := p.total.Load()
	if total <= 0 {
		return
	}
	done, total = clampProgress(done, total)
	if p.lastDone.Load() == done && p.lastTotal.Load() == total {
		return
	}
	p.lastDone.Store(done)
	p.lastTotal.Store(total)
	outputMu.Lock()
	defer outputMu.Unlock()
	activeBarPtr = p
	p.renderUnlocked()
}

func formatProgressBar(label string, done, total int64, width int, speed float64, showSpeed bool) string {
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
	if !showSpeed {
		return fmt.Sprintf("%s [%s] %3d%% (%d/%d)", label, bar, percent, done, total)
	}
	return fmt.Sprintf("%s [%s] %3d%% (%d/%d, %s)", label, bar, percent, done, total, formatByteSpeed(speed))
}

func formatFancyBar(label string, done, total int64, width int, speed float64, showSpeed bool) string {
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
	bar := ansiGreen + strings.Repeat("━", filled) + ansiGray + strings.Repeat("━", width-filled) + ansiReset
	pctColor := ansiCyan
	suffix := ""
	if done == total {
		pctColor = ansiGreen
		suffix = " " + ansiGreen + "✓" + ansiReset
	}
	if !showSpeed {
		return fmt.Sprintf(ansiBold+"%s"+ansiReset+" %s %s%3d%%"+ansiReset+" (%d/%d)%s", label, bar, pctColor, percent, done, total, suffix)
	}
	return fmt.Sprintf(ansiBold+"%s"+ansiReset+" %s %s%3d%%"+ansiReset+" (%d/%d, %s)%s", label, bar, pctColor, percent, done, total, formatByteSpeed(speed), suffix)
}

func formatByteSpeed(bytesPerSecond float64) string {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	const (
		mb = 1024.0 * 1024.0
		gb = 1024.0 * mb
	)
	if bytesPerSecond >= gb {
		return fmt.Sprintf("%.1f GB/s", bytesPerSecond/gb)
	}
	return fmt.Sprintf("%.1f MB/s", bytesPerSecond/mb)
}

func sizeOfReader(reader io.Reader) int64 {
	sizer, ok := reader.(interface{ Size() int64 })
	if !ok {
		return 0
	}
	size := sizer.Size()
	if size <= 0 {
		return 0
	}
	return size
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

// isNonRetryableHTTPErr returns true if err contains an HTTP 401 or 403 status,
// indicating an authentication/authorization failure that should not be retried.
func isNonRetryableHTTPErr(err error) bool {
	var hfErr *hf.HTTPStatusError
	if errors.As(err, &hfErr) {
		if hfErr.StatusCode == 401 || hfErr.StatusCode == 403 {
			return true
		}
	}
	var azErr *azcore.ResponseError
	if errors.As(err, &azErr) {
		if azErr.StatusCode == 401 || azErr.StatusCode == 403 {
			return true
		}
	}
	return false
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
		if isNonRetryableHTTPErr(err) {
			return err
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
	progress := newProgressBar(total, label, quiet, false)
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

func runOpPoolWithRetryProgressBytes[T any](ctx context.Context, concurrency int, retryCount int, total int, quiet bool, label string, producer func(chan<- T) error, worker func(T, bool) (int64, error)) error {
	progress := newProgressBar(total, label, quiet, true)
	err := runOpPoolWithRetry(ctx, concurrency, retryCount, producer, func(op T) error {
		trackBytes := progress != nil
		bytesDone, err := worker(op, trackBytes)
		if progress != nil && err == nil {
			progress.AddBytes(bytesDone)
			progress.Increment()
		}
		return err
	})
	if progress != nil {
		progress.Finish()
	}
	return err
}

type taskPair struct {
	src string
	dst string
}

const maxTaskfileLineSize = 4 * 1024 * 1024

func parseTaskPairLine(line string, lineNo int) (taskPair, error) {
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return taskPair{}, fmt.Errorf("taskfile: line %d: expected exactly two whitespace-separated fields `src dst` (paths with spaces are not supported)", lineNo)
	}
	return taskPair{src: parts[0], dst: parts[1]}, nil
}

func loadTaskPairs(taskfile string) ([]taskPair, error) {
	var (
		reader io.Reader
		file   *os.File
		err    error
	)
	if taskfile == "-" {
		reader = os.Stdin
	} else {
		file, err = os.Open(taskfile)
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = file.Close()
		}()
		reader = file
	}

	var tasks []taskPair
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxTaskfileLineSize)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		task, err := parseTaskPairLine(line, lineNo)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tasks, nil
}

func loadTaskState(path string) (fileState map[string]struct{}, taskCheckpoints map[string]struct{}, err error) {
	fileState = map[string]struct{}{}
	taskCheckpoints = map[string]struct{}{}
	if path == "" {
		return fileState, taskCheckpoints, nil
	}

	file, ferr := os.Open(path)
	if ferr != nil {
		if os.IsNotExist(ferr) {
			return fileState, taskCheckpoints, nil
		}
		return nil, nil, ferr
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxTaskfileLineSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, taskCheckpointPrefix) {
			taskCheckpoints[line] = struct{}{}
		} else {
			fileState[line] = struct{}{}
		}
	}
	if serr := scanner.Err(); serr != nil {
		return nil, nil, serr
	}
	return fileState, taskCheckpoints, nil
}

type taskStateAppender struct {
	mu   sync.Mutex
	file *os.File
}

func newTaskStateAppender(path string) (*taskStateAppender, error) {
	if path == "" {
		return &taskStateAppender{}, nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &taskStateAppender{file: file}, nil
}

func (a *taskStateAppender) append(taskKey string) error {
	if a.file == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.file.WriteString(taskKey + "\n"); err != nil {
		return a.closeOnError(err)
	}

	return nil
}

func (a *taskStateAppender) appendCheckpoint(taskKey string) error {
	if a.file == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.file.WriteString(taskKey + "\n"); err != nil {
		return a.closeOnError(err)
	}

	if err := a.file.Sync(); err != nil {
		return a.closeOnError(err)
	}

	return nil
}

func (a *taskStateAppender) closeOnError(err error) error {
	if a.file == nil {
		return err
	}
	if cerr := a.file.Close(); cerr != nil {
		a.file = nil
		return errors.Join(err, cerr)
	}
	a.file = nil
	return err
}

func (a *taskStateAppender) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	if serr := a.file.Sync(); serr != nil {
		_ = a.file.Close()
		a.file = nil
		return serr
	}
	err := a.file.Close()
	a.file = nil
	return err
}

const taskCheckpointPrefix = "TASK\t"

func taskStateKey(src, dst string) string {
	return src + " -> " + dst
}

func taskCheckpointKey(src, dst string) string {
	return taskCheckpointPrefix + src + " -> " + dst
}

type taskTracker struct {
	remaining atomic.Int64
	key       string // task checkpoint key
}

type cpTask struct {
	src     string
	dst     string
	key     string
	tracker *taskTracker // nil when no task-level checkpoint tracking
}

// expandCPTask streams file-level copy tasks for a taskfile pair via the emit
// callback. When the source is directory-like it expands recursively and calls
// emit for each discovered file; for file-like sources it emits a single task.
// Returning a non-nil error from emit stops expansion early.
func expandCPTask(ctx context.Context, task taskPair, emit func(cpTask) error) error {
	if isHF(task.src) {
		hfPath, err := hf.Parse(task.src)
		if err != nil {
			return err
		}
		if hfPath.File != "" {
			return emit(cpTask{src: task.src, dst: task.dst, key: taskStateKey(task.src, task.dst)})
		}
	}

	if isAz(task.src) {
		sap, err := azblob.Parse(task.src)
		if err != nil {
			return err
		}
		if !sap.IsDirLike() {
			return emit(cpTask{src: task.src, dst: task.dst, key: taskStateKey(task.src, task.dst)})
		}
	} else if !isHF(task.src) {
		if info, err := os.Stat(task.src); err != nil || !info.IsDir() {
			return emit(cpTask{src: task.src, dst: task.dst, key: taskStateKey(task.src, task.dst)})
		}
	}

	if isAz(task.dst) {
		dap, err := azblob.Parse(task.dst)
		if err != nil {
			return err
		}
		for result := range bbbfs.ListRecursive(ctx, task.src) {
			if result.Err != nil {
				return result.Err
			}
			entry := result.Entry
			if entry.IsDir {
				continue
			}
			if err := emit(cpTask{
				src: entry.Path,
				dst: dap.Child(filepath.ToSlash(entry.Name)).String(),
				key: taskStateKey(entry.Path, task.dst),
			}); err != nil {
				return err
			}
		}
		return nil
	}
	for result := range bbbfs.ListRecursive(ctx, task.src) {
		if result.Err != nil {
			return result.Err
		}
		entry := result.Entry
		if entry.IsDir {
			continue
		}
		if err := emit(cpTask{
			src: entry.Path,
			dst: filepath.Join(task.dst, entry.Name),
			key: taskStateKey(entry.Path, task.dst),
		}); err != nil {
			return err
		}
	}
	return nil
}

func cmdCP(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCP called", "args", c.Args().Slice())
	overwrite := c.Bool("f")
	quiet := c.Bool("q") || c.Bool("quiet")
	concurrency := c.Int("concurrency")
	retryCount := c.Int("retry-count")
	taskfile := c.String("taskfile")
	taskfileState := c.String("taskfile-state")

	if taskfile != "" {
		if c.Args().Len() != 0 {
			return fmt.Errorf("cp: cannot use positional args with --taskfile")
		}
		tasks, err := loadTaskPairs(taskfile)
		if err != nil {
			return err
		}
		state, taskCheckpoints, err := loadTaskState(taskfileState)
		if err != nil {
			return err
		}
		taskProgress := newProgressBar(minProgressTotal, "cp files", quiet, false)
		defer func() {
			if taskProgress != nil {
				taskProgress.Finish()
			}
		}()
		seen := make(map[string]struct{}, len(state)+len(tasks))
		for key := range state {
			seen[key] = struct{}{}
		}
		stateAppender, err := newTaskStateAppender(taskfileState)
		if err != nil {
			return err
		}

		workers := concurrency
		if workers < 1 {
			workers = 1
		}
		// Split concurrency budget: at least 1 expander, at least 1 cp worker.
		// When concurrency is high, allocate ~25% to expansion.
		expanders := max(1, workers/4)
		cpWorkers := workers - expanders
		if cpWorkers < 1 {
			cpWorkers = 1
		}
		innerConcurrency := 1
		innerQuiet := true
		workerCtx, cancel := context.WithCancel(ctx)
		defer cancel()

		var wg sync.WaitGroup
		// Buffer taskCh larger than cpWorkers so expanders can push ahead
		// without blocking while cp workers are busy.
		taskCh := make(chan cpTask, cpWorkers*4)
		var firstErr error
		var firstErrMu sync.Mutex
		var totalPending atomic.Int64
		var queued atomic.Bool

		setErr := func(err error) {
			firstErrMu.Lock()
			if firstErr == nil {
				firstErr = err
				cancel()
			}
			firstErrMu.Unlock()
		}

		for i := 0; i < cpWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-workerCtx.Done():
						return
					case task, ok := <-taskCh:
						if !ok {
							return
						}
						slog.Debug("cp: start", "src", task.src, "dst", task.dst)
						if err := cmdCPPaths(workerCtx, overwrite, innerQuiet, innerConcurrency, retryCount, []string{task.src}, task.dst); err != nil {
							setErr(err)
							return
						}
						slog.Debug("cp: done", "src", task.src, "dst", task.dst)
						if taskfileState != "" {
							if err := stateAppender.append(task.key); err != nil {
								setErr(err)
								return
							}
							if task.tracker != nil && task.tracker.remaining.Add(-1) == 0 {
								if err := stateAppender.appendCheckpoint(task.tracker.key); err != nil {
									setErr(err)
									return
								}
							}
						}
						if taskProgress != nil {
							taskProgress.Increment()
						}
					}
				}
			}()
		}

		// Dedicated expander pool uses goroutines from the concurrency budget.
		if expanders > len(tasks) {
			expanders = len(tasks)
		}
		pairCh := make(chan taskPair, expanders*2)
		var seenMu sync.Mutex
		var expandWG sync.WaitGroup
		for i := 0; i < expanders; i++ {
			expandWG.Add(1)
			go func() {
				defer expandWG.Done()
				for {
					select {
					case <-workerCtx.Done():
						return
					case task, ok := <-pairCh:
						if !ok {
							return
						}
						cpKey := taskCheckpointKey(task.src, task.dst)
						if _, done := taskCheckpoints[cpKey]; done {
							if !quiet {
								lockedFprintf(os.Stderr, "cp: skip already completed task %s -> %s\n", task.src, task.dst)
							}
							if taskProgress != nil {
								taskProgress.SetTotal(clampProgressTotal(totalPending.Add(1)))
								taskProgress.Increment()
							}
							continue
						}
						if !quiet {
							lockedFprintf(os.Stderr, "cp: listing %s -> %s\n", task.src, task.dst)
						}
						var tracker *taskTracker
						if taskfileState != "" {
							tracker = &taskTracker{key: cpKey}
						}
						var pendingCount int64
						expandEmit := func(expandedTask cpTask) error {
							seenMu.Lock()
							_, alreadySeen := seen[expandedTask.key]
							if !alreadySeen {
								seen[expandedTask.key] = struct{}{}
							}
							seenMu.Unlock()
							if alreadySeen {
								_, inState := state[expandedTask.key]
								if !quiet && inState {
									lockedFprintf(os.Stderr, "cp: skip already copied %s -> %s\n", expandedTask.src, expandedTask.dst)
								}
								if taskProgress != nil && inState {
									taskProgress.SetTotal(clampProgressTotal(totalPending.Add(1)))
									taskProgress.Increment()
								}
								return nil
							}
							expandedTask.tracker = tracker
							pendingCount++
							select {
							case <-workerCtx.Done():
								return workerCtx.Err()
							case taskCh <- expandedTask:
								slog.Debug("cp: queued", "src", expandedTask.src, "dst", expandedTask.dst)
								queued.Store(true)
								if taskProgress != nil {
									taskProgress.SetTotal(clampProgressTotal(totalPending.Add(1)))
								}
							}
							return nil
						}
						if err := retryOp(workerCtx, retryCount, func() error {
							pendingCount = 0
							return expandCPTask(workerCtx, task, expandEmit)
						}); err != nil {
							setErr(fmt.Errorf("cp: expand task %s -> %s: %w", task.src, task.dst, err))
							return
						}
						if tracker != nil {
							tracker.remaining.Store(pendingCount)
							if pendingCount == 0 {
								if err := stateAppender.appendCheckpoint(cpKey); err != nil {
									setErr(err)
									return
								}
							}
						}
					}
				}
			}()
		}
	enqueueTasks:
		for _, task := range tasks {
			select {
			case <-workerCtx.Done():
				break enqueueTasks
			case pairCh <- task:
			}
		}
		close(pairCh)
		expandWG.Wait()
		close(taskCh)
		wg.Wait()
		if !queued.Load() && firstErr == nil {
			if err := stateAppender.close(); err != nil {
				return err
			}
			return nil
		}

		if firstErr != nil {
			_ = stateAppender.close()
			return firstErr
		}
		if err := stateAppender.close(); err != nil {
			return err
		}
		return nil
	}

	if c.Args().Len() < 2 {
		return fmt.Errorf("cp: need srcs dst")
	}
	srcs := make([]string, c.Args().Len()-1)
	for i := 0; i < len(srcs); i++ {
		srcs[i] = c.Args().Get(i)
	}
	dst := c.Args().Get(c.Args().Len() - 1)
	return cmdCPPaths(ctx, overwrite, quiet, concurrency, retryCount, srcs, dst)
}

func cmdCPPaths(ctx context.Context, overwrite, quiet bool, concurrency, retryCount int, srcs []string, dst string) error {
	if isHF(dst) {
		return fmt.Errorf("cp: hf:// only supported as source")
	}
	dstAz := isAz(dst)
	// Determine if dst is directory (local or Azure)
	isDstDir := false
	if dstAz {
		dap, err := azblob.Parse(dst)
		if err != nil {
			return fmt.Errorf("cp: parse destination %q: %w", dst, err)
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
		size      int64
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
			return fmt.Errorf("cp: %s -> %s: %w", op.src, op.dst, err)
		}
	}
	if err := runOpPoolWithRetryProgressBytes(ctx, concurrency, retryCount, len(fileOps), quiet, "cp", func(pending chan<- cpFileOp) error {
		for _, op := range fileOps {
			if err := sendOp(ctx, pending, op); err != nil {
				return err
			}
		}
		return nil
	}, func(op cpFileOp, trackBytes bool) (int64, error) {
		size := op.size
		if trackBytes && size <= 0 {
			info, err := bbbfs.Resolve(op.src).Stat(ctx, op.src)
			if err != nil {
				slog.Debug("unable to stat source size for progress speed", "src", op.src, "error", err)
			} else {
				size = info.Size
			}
		}
		if op.srcHF {
			err := copyHFFile(ctx, op.hf, op.base, op.dst, op.dstAz, overwrite, quiet, isDstDir)
			return size, err
		}
		if op.srcAz && op.dstAz {
			dap, _ := azblob.Parse(op.dst)
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					return 0, errors.New("cp: destination exists")
				}
			}
			var copyBar *progressBar
			if !quiet && isTerminal(os.Stderr) {
				copyBar = newProgressBar(100, path.Base(op.src), false, true)
			}
			if err := azblob.CopyBlobServerSide(ctx, op.srcAzPath, dap, func(copied, total int64) {
				if copyBar == nil || total <= 0 {
					return
				}
				copyBar.bytesDone.Store(copied)
				copyBar.render(copied * 100 / total)
			}); err != nil {
				if copyBar != nil {
					copyBar.Finish()
				}
				return 0, err
			}
			if copyBar != nil {
				copyBar.Finish()
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
			}
			return size, nil
		}
		if op.srcAz && !op.dstAz {
			reader, err := azblob.DownloadStream(ctx, op.srcAzPath)
			if err != nil {
				return 0, err
			}
			if !overwrite {
				if _, err := os.Stat(op.dst); err == nil {
					if cerr := reader.Close(); cerr != nil {
						return 0, cerr
					}
					return 0, errors.New("cp: destination exists")
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return writeStreamToFile(op.dst, r, 0o644)
			}); err != nil {
				return 0, err
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
			}
			return size, nil
		}
		if !op.srcAz && op.dstAz {
			dap, _ := azblob.Parse(op.dst)
			reader, err := os.Open(op.src)
			if err != nil {
				return 0, err
			}
			if !overwrite {
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					if cerr := reader.Close(); cerr != nil {
						return 0, cerr
					}
					return 0, errors.New("cp: destination exists")
				}
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return azblob.UploadStream(ctx, dap, r)
			}); err != nil {
				return 0, err
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
			}
			return size, nil
		}
		if err := fsops.CopyFile(op.src, op.dst, overwrite); err != nil {
			return 0, fmt.Errorf("cp: %w", err)
		}
		if !quiet {
			lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
		}
		return size, nil
	}); err != nil {
		return fmt.Errorf("cp: file operations: %w", err)
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
	return runOpPoolWithRetryProgressBytes(ctx, concurrency, retryCount, len(files), quiet, "cp", func(pending chan<- hfOp) error {
		for _, file := range files {
			if err := sendOp(ctx, pending, hfOp{file: file}); err != nil {
				return err
			}
		}
		return nil
	}, func(op hfOp, trackBytes bool) (int64, error) {
		filePath := hf.Path{Repo: hfPath.Repo, File: op.file}
		dstPath, err := resolveDstPath(dst, dstAz, op.file, true)
		if err != nil {
			return 0, err
		}
		if !overwrite {
			if dstAz {
				dap, err := azblob.Parse(dstPath)
				if err != nil {
					return 0, err
				}
				if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
					return 0, errors.New("cp: destination must be a blob path")
				}
				if _, err := azblob.HeadBlob(ctx, dap); err == nil {
					return 0, nil
				}
			} else if _, err := os.Stat(dstPath); err == nil {
				return 0, nil
			}
		}
		size := int64(0)
		if trackBytes {
			info, err := bbbfs.Resolve(filePath.String()).Stat(ctx, filePath.String())
			if err == nil {
				size = info.Size
			}
		}
		reader, err := bbbfs.Resolve(filePath.String()).Read(ctx, filePath.String())
		if err != nil {
			return 0, err
		}
		if trackBytes && size <= 0 {
			size = sizeOfReader(reader)
		}
		if err := withReadCloser(reader, func(r io.Reader) error {
			return bbbfs.Resolve(dstPath).Write(ctx, dstPath, r)
		}); err != nil {
			return 0, err
		}
		if !quiet {
			lockedPrintf("Copied %s -> %s\n", filePath.String(), dstPath)
		}
		return size, nil
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
	dry := c.Bool("dry-run")
	del := c.Bool("delete")
	quiet := c.Bool("q") || c.Bool("quiet")
	exclude := c.String("x")
	concurrency := c.Int("concurrency")
	retryCount := c.Int("retry-count")
	taskfile := c.String("taskfile")

	if taskfile != "" {
		if c.Args().Len() != 0 {
			return fmt.Errorf("sync: cannot use positional args with --taskfile")
		}
		tasks, err := loadTaskPairs(taskfile)
		if err != nil {
			return err
		}
		for _, task := range tasks {
			if err := cmdSyncPaths(ctx, dry, del, quiet, exclude, concurrency, retryCount, task.src, task.dst); err != nil {
				return err
			}
		}
		return nil
	}
	if c.Args().Len() != 2 {
		return fmt.Errorf("sync: need src dst")
	}
	src, dst := c.Args().Get(0), c.Args().Get(1)
	return cmdSyncPaths(ctx, dry, del, quiet, exclude, concurrency, retryCount, src, dst)
}

func cmdSyncPaths(ctx context.Context, dry, del, quiet bool, exclude string, concurrency, retryCount int, src, dst string) error {
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
				return fmt.Errorf("sync: %w", err)
			}
			list, err := azblob.ListRecursive(ctx, sap)
			if err != nil {
				return fmt.Errorf("sync: list %s: %w", src, err)
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
	list, listErr := fs.List(ctx, parentPath)
	if isAz(target) {
		ap, err := azblob.Parse(target)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		var totalSize int64
		var count int
		if err := azblob.ListStream(ctx, ap, func(bm azblob.BlobMeta) error {
			name := bm.Name
			if name == "" || strings.HasSuffix(name, "/") {
				return nil // skip directories
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
			return nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !machine {
			fmt.Printf("Listed %d files summing to %d bytes (%.1f MiB)\n", count, totalSize, float64(totalSize)/(1024*1024))
		}
		return nil
	}
	if listErr != nil {
		fmt.Fprintln(os.Stderr, listErr)
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
