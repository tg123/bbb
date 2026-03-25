package main

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

	"github.com/tg123/bbb/internal/bbbfs"
	"github.com/tg123/bbb/internal/fsops"
)

var mainver string = "(devel)"

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

type dialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// dnsLoggingDialContext wraps a base dialer to log DNS resolution results at
// debug level before each connection. When debug logging is not enabled the
// wrapper is a no-op and delegates directly to baseDial, so there is no extra
// overhead in normal operation. The original address is always passed through
// to baseDial, preserving Go's standard happy-eyeballs dialing behaviour.
func dnsLoggingDialContext(baseDial dialContextFunc, resolver *net.Resolver) dialContextFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if slog.Default().Enabled(ctx, slog.LevelDebug) {
			host, _, err := net.SplitHostPort(addr)
			if err == nil {
				addrs, dnsErr := resolver.LookupHost(ctx, host)
				if dnsErr != nil {
					slog.Debug("DNS lookup error", "host", host, "error", dnsErr)
				} else if len(addrs) == 0 {
					slog.Debug("DNS lookup returned no addresses", "host", host)
				} else {
					slog.Debug("DNS lookup", "host", host, "addrs", addrs)
				}
			}
		}
		return baseDial(ctx, network, addr)
	}
}

// lookupHostFunc is the signature for a DNS hostname lookup function.
type lookupHostFunc func(ctx context.Context, host string) ([]string, error)

// dnsCacheEntry stores resolved addresses with an expiry time.
type dnsCacheEntry struct {
	addrs  []string
	expiry time.Time
}

const defaultDNSCacheTTL = 5 * time.Minute

// dnsCachingDialContext wraps a base dialer to cache DNS resolution results.
// Resolved addresses are cached with a TTL (defaultDNSCacheTTL) to avoid
// serving stale records indefinitely. When the address is already an IP
// literal or SplitHostPort fails, the call is passed straight through to
// baseDial.
//
// Note: because cached addresses are dialled as IP literals, Go's standard
// Happy Eyeballs (RFC 6555) connection racing is bypassed. For bbb's primary
// workload (Azure Blob Storage endpoints that are typically single-stack)
// this has no practical impact.
func dnsCachingDialContext(baseDial dialContextFunc, resolver *net.Resolver) dialContextFunc {
	return newCachingDialContext(baseDial, resolver.LookupHost, defaultDNSCacheTTL)
}

// newCachingDialContext is the internal implementation used by
// dnsCachingDialContext. Accepting a lookupHostFunc and explicit TTL makes
// the function easy to test with deterministic inputs.
func newCachingDialContext(baseDial dialContextFunc, lookup lookupHostFunc, ttl time.Duration) dialContextFunc {
	var cache sync.Map // host → *dnsCacheEntry

	dialAddrs := func(ctx context.Context, network, port string, addrs []string) (net.Conn, error) {
		var lastErr error
		for _, a := range addrs {
			conn, dialErr := baseDial(ctx, network, net.JoinHostPort(a, port))
			if dialErr == nil {
				return conn, nil
			}
			lastErr = dialErr
		}
		return nil, lastErr
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return baseDial(ctx, network, addr)
		}

		// Already an IP – nothing to cache.
		if net.ParseIP(host) != nil {
			return baseDial(ctx, network, addr)
		}

		// Try the cache first (with TTL check).
		if v, ok := cache.Load(host); ok {
			entry := v.(*dnsCacheEntry)
			if time.Now().Before(entry.expiry) {
				slog.Debug("DNS cache hit", "host", host, "addrs", entry.addrs)
				return dialAddrs(ctx, network, port, entry.addrs)
			}
			cache.Delete(host)
		}

		// Cache miss or expired – resolve and store.
		addrs, lookupErr := lookup(ctx, host)
		if lookupErr != nil {
			slog.Debug("DNS lookup error", "host", host, "error", lookupErr)
			return baseDial(ctx, network, addr)
		}
		if len(addrs) == 0 {
			slog.Debug("DNS lookup returned no addresses", "host", host)
			return baseDial(ctx, network, addr)
		}

		cache.Store(host, &dnsCacheEntry{
			addrs:  addrs,
			expiry: time.Now().Add(ttl),
		})
		slog.Debug("DNS cache miss, resolved", "host", host, "addrs", addrs)

		return dialAddrs(ctx, network, port, addrs)
	}
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
			&cli.StringFlag{Name: "taskfile", Hidden: true},
			&cli.StringFlag{Name: "state", Hidden: true},
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
			slog.SetDefault(slog.New(&barAwareHandler{inner: handler}))
			slog.Debug("Logger initialized", "level", lvlStr)

			if transport, ok := http.DefaultTransport.(*http.Transport); ok {
				transport = transport.Clone()
				baseDial := (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext

				switch strings.ToLower(os.Getenv("BBB_DNS_CACHE")) {
				case "1", "true", "yes", "on":
					transport.DialContext = dnsCachingDialContext(baseDial, net.DefaultResolver)
					slog.Info("DNS caching enabled",
						"env", "BBB_DNS_CACHE",
						"ttl", defaultDNSCacheTTL,
					)
				default:
					transport.DialContext = dnsLoggingDialContext(baseDial, net.DefaultResolver)
				}

				http.DefaultTransport = transport
			}

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
							if !bbbfs.IsAz(target) {
								return fmt.Errorf("mkcontainer: only az:// paths supported")
							}
							account, container, err := bbbfs.AzAccountContainer(target)
							if err != nil {
								return fmt.Errorf("mkcontainer: %w", err)
							}
							if container == "" {
								return fmt.Errorf("mkcontainer: need az://account/container")
							}
							err = bbbfs.MkDir(ctx, target)
							if err != nil {
								return err
							}
							fmt.Printf("Created container %s/%s\n", account, container)
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
				UsageText: "bbb lstree [-l|--long] [--machine] [-s|--relative] [--concurrency N] [path]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "l", Aliases: []string{"long"}, Usage: "List information about each file"},
					&cli.BoolFlag{Name: "machine", Usage: "Machine-readable (tab-separated) output"},
					&cli.BoolFlag{Name: "s", Aliases: []string{"relative"}, Usage: "Show relative paths"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent listing requests", Value: runtime.NumCPU()},
				},
				Action: cmdLSTree,
			},
			{
				Name:      "llr",
				Usage:     "Alias for 'lstree -l' (recursive long file list)",
				UsageText: "bbb llr [-s|--relative] [--machine] [--concurrency N] [path]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "s", Aliases: []string{"relative"}, Usage: "Show relative paths"},
					&cli.BoolFlag{Name: "machine", Usage: "Machine-readable (tab-separated) output"},
					&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent listing requests", Value: runtime.NumCPU()},
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
				UsageText: "bbb cp [--taskfile FILE|--taskfile -] [--state FILE] [-q|--quiet] [--concurrency N] [--retry-count N]\n   or: bbb cp [--state FILE] [-q|--quiet] [--concurrency N] [--retry-count N] srcs [srcs ...] dst",
				Aliases:   []string{"cpr", "cptree"},
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "taskfile", Usage: "Task file containing one `src dst` pair per line (`-` for stdin)"},
					&cli.StringFlag{Name: "state", Usage: "State file for crash recovery"},
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
				UsageText: "bbb sync [--taskfile FILE|--taskfile -] [--state FILE] [-q|--quiet] [--delete] [-x EXCLUDE|--exclude EXCLUDE] [--concurrency N] [--retry-count N]\n   or: bbb sync [--state FILE] [-q|--quiet] [--delete] [-x EXCLUDE|--exclude EXCLUDE] [--concurrency N] [--retry-count N] src dst",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "taskfile", Usage: "Task file containing one `src dst` pair per line (`-` for stdin)"},
					&cli.StringFlag{Name: "state", Usage: "State file for crash recovery"},
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
		// List may fail on file targets (e.g. ENOTDIR for local paths).
		// Fall back to Stat when no wildcard was used.
		if pattern == "" {
			st, statErr := fs.Stat(ctx, parentPath)
			if statErr == nil && !st.IsDir {
				entries = []bbbfs.Entry{st}
			} else {
				return err
			}
		} else {
			return err
		}
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
	if conc := c.Int("concurrency"); conc > 0 {
		ctx = bbbfs.WithScanConcurrency(ctx, conc)
	}

	parentPath, pattern := splitWildcard(root)
	var count int64
	var totalSize int64
	for result := range bbbfs.ListRecursive(ctx, parentPath) {
		if result.Err != nil {
			return result.Err
		}
		entry := result.Entry
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
		totalSize += entry.Size
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
				fmt.Printf("%10s  %s  %s\n", formatSize(entry.Size), mod, display)
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
		noun := "files"
		if count == 1 {
			noun = "file"
		}
		fmt.Printf("Listed %d %s summing to %s (%d bytes)\n", count, noun, formatSize(totalSize), totalSize)
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
		if bbbfs.IsAz(p) {
			if err := bbbfs.Touch(ctx, p); err != nil {
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
		if bbbfs.IsNonRetryableHTTPErr(err) {
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

func cmdCP(ctx context.Context, c *cli.Command) error {
	slog.Debug("cmdCP called", "args", c.Args().Slice())
	overwrite := c.Bool("f")
	quiet := c.Bool("q") || c.Bool("quiet")
	concurrency := c.Int("concurrency")
	ctx = bbbfs.WithScanConcurrency(ctx, concurrency)
	retryCount := c.Int("retry-count")
	taskfile := c.String("taskfile")
	if taskfile == "" {
		taskfile = c.Root().String("taskfile")
	}
	stateFile := c.String("state")
	if stateFile == "" {
		stateFile = c.Root().String("state")
	}

	var tasks []taskPair
	if taskfile != "" {
		if c.Args().Len() != 0 {
			return fmt.Errorf("cp: cannot use positional args with --taskfile")
		}
		var err error
		tasks, err = loadTaskPairs(taskfile)
		if err != nil {
			return err
		}
	} else {
		// Convert positional args into task pairs so both modes share the
		// same execution path (expansion, state tracking, progress bars).
		if c.Args().Len() < 2 {
			return fmt.Errorf("cp: need srcs dst")
		}
		dst := c.Args().Get(c.Args().Len() - 1)
		for i := 0; i < c.Args().Len()-1; i++ {
			tasks = append(tasks, taskPair{src: c.Args().Get(i), dst: dst})
		}
	}

	return runCPTasks(ctx, tasks, overwrite, quiet, concurrency, retryCount, stateFile)
}

// runCPTasks executes a list of task pairs through the unified expansion +
// parallel copy pipeline. Both taskfile mode and positional-arg mode convert
// their inputs to []taskPair and call this function, ensuring a single code
// path for state tracking, progress bars, and concurrency control.
func runCPTasks(ctx context.Context, tasks []taskPair, overwrite, quiet bool, concurrency, retryCount int, stateFile string) error {
	state, taskCheckpoints, err := loadTaskState(stateFile)
	if err != nil {
		return err
	}
	// Streaming progress bar: total starts at 0 and grows as files are
	// discovered during expansion. The bar stays invisible until the
	// first file is found, then updates on every change.
	taskProgress := newStreamingProgressBar("cp files", quiet, true)
	if taskProgress != nil {
		taskProgress.pinBottom = true
	}
	defer func() {
		if taskProgress != nil {
			taskProgress.Finish()
		}
	}()
	seen := make(map[string]struct{}, len(state)+len(tasks))
	for key := range state {
		seen[key] = struct{}{}
	}
	stateAppender, err := newTaskStateAppender(stateFile)
	if err != nil {
		return err
	}

	workers := concurrency
	if workers < 1 {
		workers = 1
	}
	// Expanders discover files (via listing) and push them to the task channel.
	// Listing runs as a sequential flat pager, so each expander is lightweight.
	// Multiple expanders help when there are multiple source→destination pairs;
	// for a single pair, only 1 expander runs (capped below by len(tasks)).
	expanders := max(1, workers/4)
	cpWorkers := max(1, workers-expanders)
	// Distribute the concurrency budget between file-level and block-level
	// parallelism: total goroutines = cpWorkers × innerConcurrency ≤ concurrency.
	// For many small files (≤1 block each), cpWorkers dominates and each file
	// finishes with a single StageBlockFromURL. For few large files, workers
	// naturally converge to fewer active files and each gets more block parallelism.
	// Cap cpWorkers so large files still get enough inner parallelism.
	maxCPWorkers := max(2, concurrency/4)
	if cpWorkers > maxCPWorkers {
		cpWorkers = maxCPWorkers
	}
	innerConcurrency := max(1, concurrency/cpWorkers)
	innerQuiet := true
	showCopyBars := !quiet
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	// Buffer taskCh so listing can stay well ahead of copy workers.
	// A large buffer decouples listing from copying and prevents
	// scanner back-pressure.
	taskBuf := concurrency * 128
	if taskBuf < 4096 {
		taskBuf = 4096
	}
	taskCh := make(chan cpTask, taskBuf)
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
					var bytesCb func(int64)
					if taskProgress != nil {
						bytesCb = taskProgress.AddBytes
					}
					if err := cmdCPPaths(workerCtx, overwrite, innerQuiet, innerConcurrency, retryCount, []string{task.src}, task.dst, task.size, showCopyBars, bytesCb); err != nil {
						setErr(err)
						return
					}
					slog.Debug("cp: done", "src", task.src, "dst", task.dst)
					if stateFile != "" {
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
							taskProgress.SetTotal(totalPending.Add(1))
							taskProgress.Increment()
						}
						continue
					}
					if !quiet {
						lockedFprintf(os.Stderr, "cp: listing %s -> %s\n", task.src, task.dst)
					}
					var tracker *taskTracker
					if stateFile != "" {
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
								taskProgress.SetTotal(totalPending.Add(1))
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
								taskProgress.SetTotal(totalPending.Add(1))
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
					// Reconcile progress bar total after expansion completes
					// so it reflects all discovered files (queued + skipped).
					if taskProgress != nil {
						taskProgress.SetTotal(totalPending.Load())
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
enqueueLoop:
	for _, task := range tasks {
		select {
		case <-workerCtx.Done():
			break enqueueLoop
		case pairCh <- task:
		}
	}
	close(pairCh)
	expandWG.Wait()
	// Set the final total now that expansion is complete so the bar
	// can reach 100% once all workers finish.
	if taskProgress != nil {
		taskProgress.SetTotal(totalPending.Load())
	}
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

func cmdCPPaths(ctx context.Context, overwrite, quiet bool, concurrency, retryCount int, srcs []string, dst string, srcSize int64, showCopyBar bool, onBytes func(int64)) error {
	if bbbfs.IsHF(dst) {
		return fmt.Errorf("cp: hf:// only supported as source")
	}
	dstAz := bbbfs.IsAz(dst)
	// Determine if dst is directory (local or Azure)
	isDstDir := bbbfs.IsDirLikeFromPath(dst)
	type cpDirOp struct {
		src string
		dst string
	}
	type cpFileOp struct {
		src   string
		dst   string
		srcAz bool
		dstAz bool
		size  int64
		base  string
	}
	dirOps := make([]cpDirOp, 0, len(srcs))
	fileOps := make([]cpFileOp, 0, len(srcs))
	for _, src := range srcs {
		src := src
		srcAz := bbbfs.IsAz(src)
		base := bbbfs.BaseName(src)
		if bbbfs.IsHF(src) || srcAz {
			dirLike, err := bbbfs.IsDirLike(ctx, src)
			if err != nil {
				return err
			}
			if dirLike {
				dirOps = append(dirOps, cpDirOp{src: src, dst: dst})
				continue
			}
			// IsDirLike only checks path syntax. For Azure sources,
			// verify the blob exists; if not, the path may be a virtual
			// directory prefix. Skip the expensive Stat for HF sources.
			if srcAz {
				if _, statErr := bbbfs.Resolve(src).Stat(ctx, src); statErr != nil {
					slog.Debug("source not found as blob, trying as directory", "src", src, "error", statErr)
					dirOps = append(dirOps, cpDirOp{src: src, dst: dst})
					continue
				}
			}
			// Single file
		} else if info, err := os.Stat(src); err == nil && info.IsDir() {
			dirOps = append(dirOps, cpDirOp{src: src, dst: dst})
			continue
		}
		var dstPath string
		if isDstDir {
			var err error
			dstPath, err = bbbfs.ResolveDstPath(dst, base, false)
			if err != nil {
				return err
			}
		} else {
			dstPath = dst
		}
		fileOps = append(fileOps, cpFileOp{
			src:   src,
			dst:   dstPath,
			srcAz: srcAz,
			dstAz: dstAz,
			size:  srcSize,
			base:  base,
		})
	}
	for _, op := range dirOps {
		err := copyTree(ctx, op.src, op.dst, overwrite, quiet, "cp", concurrency, retryCount)
		if err != nil {
			return fmt.Errorf("cp: %s -> %s: %w", op.src, op.dst, err)
		}
	}
	// Distribute concurrency between file-level and block-level parallelism
	// for az→az server-side copies: total goroutines = cpPoolSize × blockConcurrency ≤ concurrency.
	cpPoolSize := concurrency
	blockConcurrency := concurrency
	for _, op := range fileOps {
		if op.srcAz && op.dstAz {
			if concurrency >= 2 {
				cpPoolSize = max(2, concurrency/4)
				if cpPoolSize > concurrency {
					cpPoolSize = concurrency
				}
			} else {
				cpPoolSize = 1
			}
			blockConcurrency = max(1, concurrency/cpPoolSize)
			break
		}
	}
	if err := runOpPoolWithRetryProgressBytes(ctx, cpPoolSize, retryCount, len(fileOps), quiet, "cp", func(pending chan<- cpFileOp) error {
		for _, op := range fileOps {
			if err := sendOp(ctx, pending, op); err != nil {
				return err
			}
		}
		return nil
	}, func(op cpFileOp, trackBytes bool) (int64, error) {
		size := op.size
		if (trackBytes || onBytes != nil) && size <= 0 {
			info, err := bbbfs.Resolve(op.src).Stat(ctx, op.src)
			if err != nil {
				slog.Debug("unable to stat source size for progress speed", "src", op.src, "error", err)
			} else {
				size = info.Size
			}
		}
		// Az→Az: server-side copy with progress
		if op.srcAz && op.dstAz {
			if !overwrite {
				if exists, _ := bbbfs.ExistsAsBlob(ctx, op.dst); exists {
					return 0, errors.New("cp: destination exists")
				}
			}
			var copyBar *progressBar
			if showCopyBar {
				copyBar = newStreamingProgressBar(path.Base(op.src), false, true)
				if copyBar != nil {
					copyBar.byteSized = true
				}
			}
			var lastReported atomic.Int64
			if err := bbbfs.CopyServerSide(ctx, op.src, op.dst, blockConcurrency, size, func(copied, total int64) {
				if total <= 0 {
					return
				}
				// Report incremental bytes to the overall taskbar.
				// Use CAS loop because callbacks arrive from parallel goroutines.
				if onBytes != nil {
					for {
						prev := lastReported.Load()
						if copied <= prev {
							break
						}
						if lastReported.CompareAndSwap(prev, copied) {
							onBytes(copied - prev)
							break
						}
					}
				}
				if copyBar == nil {
					return
				}
				// Update done/bytesDone before SetTotal so the first
				// render (triggered by SetTotal when total transitions
				// from 0 to N) shows actual progress instead of 0%.
				atomicMax(&copyBar.bytesDone, copied)
				atomicMax(&copyBar.done, copied)
				copyBar.SetTotal(total)
				copyBar.render(copied)
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
		// Generic copy via bbbfs Read+Write (covers HF→local, HF→Az, Az→local, local→Az)
		if !overwrite {
			if exists, _ := bbbfs.ExistsAsBlob(ctx, op.dst); exists {
				return 0, errors.New("cp: destination exists")
			}
		}
		if bbbfs.IsRemote(op.src) || bbbfs.IsRemote(op.dst) {
			reader, err := bbbfs.Resolve(op.src).Read(ctx, op.src)
			if err != nil {
				return 0, err
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return bbbfs.Resolve(op.dst).Write(ctx, op.dst, r)
			}); err != nil {
				return 0, err
			}
		} else {
			if err := fsops.CopyFile(op.src, op.dst, overwrite); err != nil {
				return 0, fmt.Errorf("cp: %w", err)
			}
		}
		if !quiet {
			lockedPrintf("Copied %s -> %s\n", op.src, op.dst)
		}
		if onBytes != nil {
			onBytes(size)
		}
		return size, nil
	}); err != nil {
		return fmt.Errorf("cp: file operations: %w", err)
	}
	return nil
}

func copyTree(ctx context.Context, src, dst string, overwrite, quiet bool, errPrefix string, concurrency int, retryCount int) error {
	if bbbfs.IsRemote(src) || bbbfs.IsRemote(dst) {
		// Remote copy: list source files and copy each
		srcAz, dstAz := bbbfs.IsAz(src), bbbfs.IsAz(dst)
		if srcAz && dstAz {
			// Az→Az: server-side copy with per-file progress.
			// Stream listing into the worker pool so copy work starts
			// while listing is still in progress.
			type ssOp struct {
				name string
			}
			// Distribute concurrency between file-level and block-level parallelism:
			// total goroutines = fileWorkers × blockConcurrency ≤ concurrency.
			fileWorkers := max(2, concurrency/4)
			if concurrency < 2 {
				fileWorkers = 1
			} else if fileWorkers > concurrency {
				fileWorkers = concurrency
			}
			blockConcurrency := max(1, concurrency/fileWorkers)
			var totalItems atomic.Int64
			copyTreeProgress := newStreamingProgressBar(errPrefix, quiet, false)
			if copyTreeProgress != nil {
				copyTreeProgress.pinBottom = true
			}
			poolErr := runOpPoolWithRetry(ctx, fileWorkers, retryCount, func(pending chan<- ssOp) error {
				return bbbfs.ListRecursiveWithSizeStream(ctx, src, func(entry bbbfs.Entry) error {
					if copyTreeProgress != nil {
						copyTreeProgress.SetTotal(totalItems.Add(1))
					}
					return sendOp(ctx, pending, ssOp{name: entry.Name})
				})
			}, func(work ssOp) error {
				if copyTreeProgress != nil {
					defer copyTreeProgress.Increment()
				}
				srcChild := bbbfs.ChildPath(src, work.name)
				dstChild := bbbfs.ChildPath(dst, work.name)
				if !overwrite {
					if exists, _ := bbbfs.ExistsAsBlob(ctx, dstChild); exists {
						return nil
					}
				}
				var copyBar *progressBar
				if !quiet {
					copyBar = newStreamingProgressBar(path.Base(work.name), false, true)
					if copyBar != nil {
						copyBar.byteSized = true
					}
				}
				if err := bbbfs.CopyServerSide(ctx, srcChild, dstChild, blockConcurrency, 0, func(copied, total int64) {
					if total <= 0 || copyBar == nil {
						return
					}
					atomicMax(&copyBar.bytesDone, copied)
					atomicMax(&copyBar.done, copied)
					copyBar.SetTotal(total)
					copyBar.render(copied)
				}); err != nil {
					if copyBar != nil {
						copyBar.Finish()
					}
					lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, work.name, err)
					return err
				}
				if copyBar != nil {
					copyBar.Finish()
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", srcChild, dstChild)
				}
				return nil
			})
			if copyTreeProgress != nil {
				copyTreeProgress.Finish()
			}
			return poolErr
		}
		// Generic remote copy: read via bbbfs + write via bbbfs
		type remoteCopyOp struct {
			name string
		}
		var ops []remoteCopyOp
		var walkIssues bool
		if bbbfs.IsRemote(src) {
			for result := range bbbfs.ListRecursive(ctx, src) {
				if result.Err != nil {
					return result.Err
				}
				if result.Entry.IsDir {
					continue
				}
				ops = append(ops, remoteCopyOp{name: result.Entry.Name})
			}
		} else {
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
				ops = append(ops, remoteCopyOp{name: rel})
				return nil
			})
			if walkErr != nil {
				return walkErr
			}
		}
		var walkIssueErr error
		if walkIssues {
			walkIssueErr = fmt.Errorf("%s: one or more files failed to copy", errPrefix)
		}
		err := runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(ops), quiet, errPrefix, func(pending chan<- remoteCopyOp) error {
			for _, op := range ops {
				if err := sendOp(ctx, pending, op); err != nil {
					return err
				}
			}
			return nil
		}, func(work remoteCopyOp) error {
			srcPath := bbbfs.ChildPath(src, work.name)
			dstPath := bbbfs.ChildPath(dst, work.name)
			if !overwrite {
				if exists, _ := bbbfs.ExistsAsBlob(ctx, dstPath); exists {
					return nil
				}
			}
			reader, err := bbbfs.Resolve(srcPath).Read(ctx, srcPath)
			if err != nil {
				lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, work.name, err)
				return err
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return bbbfs.Resolve(dstPath).Write(ctx, dstPath, r)
			}); err != nil {
				lockedFprintf(os.Stderr, "%s: %s: %v\n", errPrefix, work.name, err)
				return err
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", srcPath, dstPath)
			}
			return nil
		})
		if walkIssueErr != nil {
			return errors.Join(err, walkIssueErr)
		}
		return err
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

func withReadCloser(reader io.ReadCloser, fn func(io.Reader) error) error {
	defer func() {
		_ = reader.Close()
	}()
	return fn(reader)
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
	ctx = bbbfs.WithScanConcurrency(ctx, concurrency)
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
		if bbbfs.IsAz(op.path) {
			if err := bbbfs.Delete(ctx, op.path); err != nil {
				if force {
					lower := strings.ToLower(err.Error())
					if strings.Contains(lower, "notfound") ||
						strings.Contains(lower, "parse") ||
						strings.Contains(lower, "invalid") {
						return nil
					}
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
	ctx = bbbfs.WithScanConcurrency(ctx, concurrency)
	retryCount := c.Int("retry-count")
	if c.Args().Len() != 1 {
		return fmt.Errorf("rmtree: need directory root")
	}
	root := c.Args().Get(0)
	if bbbfs.IsAz(root) {
		files, err := bbbfs.ListFilesFlat(ctx, root)
		if err != nil {
			return err
		}
		type rmTreeOp struct {
			name string
		}
		ops := make([]rmTreeOp, 0, len(files))
		for _, name := range files {
			if name == "" {
				continue
			}
			ops = append(ops, rmTreeOp{name: name})
		}
		return runOpPoolWithRetryProgress(ctx, concurrency, retryCount, len(ops), quiet, "rmtree", func(pending chan<- rmTreeOp) error {
			for _, op := range ops {
				if err := sendOp(ctx, pending, op); err != nil {
					return err
				}
			}
			return nil
		}, func(op rmTreeOp) error {
			childPath := bbbfs.ChildPath(root, op.name)
			if err := bbbfs.Delete(ctx, childPath); err != nil {
				lockedFprintf(os.Stderr, "rmtree: %s: %v\n", op.name, err)
				return err
			}
			if !quiet {
				lockedPrintf("Deleted %s\n", childPath)
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
	if bbbfs.IsAz(p) {
		portal, direct, err := bbbfs.ParseShareInfo(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "share: %s: %v\n", p, err)
			return err
		}
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

func syncRemoteFiles(ctx context.Context, src string, excludeMatch func(string) bool) ([]string, error) {
	files, err := bbbfs.ListFilesFlat(ctx, src)
	if err != nil {
		return nil, err
	}
	return filterExclude(files, excludeMatch), nil
}

func filterExclude(files []string, excludeMatch func(string) bool) []string {
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
	ctx = bbbfs.WithScanConcurrency(ctx, concurrency)
	retryCount := c.Int("retry-count")
	taskfile := c.String("taskfile")
	if taskfile == "" {
		taskfile = c.Root().String("taskfile")
	}
	stateFile := c.String("state")
	if stateFile == "" {
		stateFile = c.Root().String("state")
	}

	if taskfile != "" {
		if c.Args().Len() != 0 {
			return fmt.Errorf("sync: cannot use positional args with --taskfile")
		}
		tasks, err := loadTaskPairs(taskfile)
		if err != nil {
			return err
		}
		_, taskCheckpoints, err := loadTaskState(stateFile)
		if err != nil {
			return err
		}
		var stateAppender *taskStateAppender
		if !dry {
			stateAppender, err = newTaskStateAppender(stateFile)
			if err != nil {
				return err
			}
		}
		for _, task := range tasks {
			cpKey := taskCheckpointKey(task.src, task.dst)
			if _, done := taskCheckpoints[cpKey]; done {
				if !quiet {
					lockedFprintf(os.Stderr, "sync: skip already completed task %s -> %s\n", task.src, task.dst)
				}
				continue
			}
			if err := cmdSyncPaths(ctx, dry, del, quiet, exclude, concurrency, retryCount, task.src, task.dst); err != nil {
				if stateAppender != nil {
					_ = stateAppender.close()
				}
				return err
			}
			if stateAppender != nil {
				if err := stateAppender.appendCheckpoint(cpKey); err != nil {
					return err
				}
			}
		}
		if stateAppender != nil {
			if err := stateAppender.close(); err != nil {
				return err
			}
		}
		return nil
	}
	if c.Args().Len() != 2 {
		return fmt.Errorf("sync: need src dst")
	}
	src, dst := c.Args().Get(0), c.Args().Get(1)
	if stateFile != "" {
		state, _, err := loadTaskState(stateFile)
		if err != nil {
			return err
		}
		key := taskStateKey(src, dst)
		if _, done := state[key]; done {
			if !quiet {
				lockedFprintf(os.Stderr, "sync: skip already completed %s -> %s\n", src, dst)
			}
			return nil
		}
		if err := cmdSyncPaths(ctx, dry, del, quiet, exclude, concurrency, retryCount, src, dst); err != nil {
			return err
		}
		if !dry {
			stateAppender, err := newTaskStateAppender(stateFile)
			if err != nil {
				return err
			}
			if err := stateAppender.append(key); err != nil {
				return err
			}
			return stateAppender.close()
		}
		return nil
	}
	return cmdSyncPaths(ctx, dry, del, quiet, exclude, concurrency, retryCount, src, dst)
}

func cmdSyncPaths(ctx context.Context, dry, del, quiet bool, exclude string, concurrency, retryCount int, src, dst string) error {
	if bbbfs.IsHF(dst) {
		return fmt.Errorf("sync: hf:// only supported as source")
	}
	srcHF := bbbfs.IsHF(src)
	if srcHF && !bbbfs.IsAz(dst) {
		return fmt.Errorf("sync: hf:// only supported with az:// destination")
	}
	if srcHF {
		dirLike, err := bbbfs.IsDirLike(ctx, src)
		if err != nil {
			return fmt.Errorf("sync: %w", err)
		}
		if !dirLike {
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
	if bbbfs.IsAz(src) || bbbfs.IsAz(dst) || srcHF {
		srcAz, dstAz := bbbfs.IsAz(src), bbbfs.IsAz(dst)
		type item struct {
			rel  string
			size int64
		}
		// Distribute concurrency between file-level and block-level parallelism
		// for Az→Az server-side copies: total goroutines = syncWorkers × blockConcurrency ≤ concurrency.
		syncWorkers := concurrency
		blockConcurrency := concurrency
		if srcAz && dstAz {
			if concurrency < 2 {
				syncWorkers = 1
				blockConcurrency = 1
			} else {
				syncWorkers = max(2, concurrency/4)
				if syncWorkers > concurrency {
					syncWorkers = concurrency
				}
				blockConcurrency = max(1, concurrency/syncWorkers)
			}
		}
		// Build producer: for Azure sources, stream listing into the worker
		// pool so processing starts while listing continues. For HF and
		// local→remote paths, collect first (these are either small or have
		// different constraints).
		var syncProgress *progressBar
		if !quiet {
			syncProgress = newStreamingProgressBar("sync", quiet, false)
			if syncProgress != nil {
				syncProgress.pinBottom = true
			}
		}
		var totalItems atomic.Int64
		producer := func(pending chan<- item) error {
			if srcAz {
				return bbbfs.ListRecursiveWithSizeStream(ctx, src, func(entry bbbfs.Entry) error {
					if entry.Name == "" || excludeMatch(entry.Name) {
						return nil
					}
					if syncProgress != nil {
						syncProgress.SetTotal(totalItems.Add(1))
					}
					return sendOp(ctx, pending, item{rel: entry.Name, size: entry.Size})
				})
			}
			// HF and local→remote: collect first, then feed
			var files []item
			if srcHF {
				list, err := syncRemoteFiles(ctx, src, excludeMatch)
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
			if syncProgress != nil {
				syncProgress.SetTotal(totalItems.Add(int64(len(files))))
			}
			for _, f := range files {
				if err := sendOp(ctx, pending, f); err != nil {
					return err
				}
			}
			return nil
		}
		workerErr := runOpPoolWithRetry(ctx, syncWorkers, retryCount, producer, func(f item) error {
			if syncProgress != nil {
				defer syncProgress.Increment()
			}
			sPath := f.rel
			srcChild := bbbfs.ChildPath(src, sPath)
			dstChild := bbbfs.ChildPath(dst, sPath)
			if srcAz && dstAz {
				if dry {
					if !quiet {
						lockedPrintln("COPY", srcChild, "->", dstChild)
					}
					return nil
				}
				var copyBar *progressBar
				if !quiet {
					copyBar = newStreamingProgressBar(path.Base(sPath), false, true)
					if copyBar != nil {
						copyBar.byteSized = true
					}
				}
				if err := bbbfs.CopyServerSide(ctx, srcChild, dstChild, blockConcurrency, f.size, func(copied, total int64) {
					if total <= 0 || copyBar == nil {
						return
					}
					atomicMax(&copyBar.bytesDone, copied)
					atomicMax(&copyBar.done, copied)
					copyBar.SetTotal(total)
					copyBar.render(copied)
				}); err != nil {
					if copyBar != nil {
						copyBar.Finish()
					}
					lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
					return fmt.Errorf("sync: %s: %w", sPath, err)
				}
				if copyBar != nil {
					copyBar.Finish()
				}
				if !quiet {
					lockedPrintf("Copied %s -> %s\n", srcChild, dstChild)
				}
				return nil
			}
			// Generic remote copy: bbbfs Read + bbbfs Write
			if dry {
				if !quiet {
					lockedPrintln("COPY", srcChild, "->", dstChild)
				}
				return nil
			}
			reader, err := bbbfs.Resolve(srcChild).Read(ctx, srcChild)
			if err != nil {
				lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
				return fmt.Errorf("sync: %s: %w", sPath, err)
			}
			if err := withReadCloser(reader, func(r io.Reader) error {
				return bbbfs.Resolve(dstChild).Write(ctx, dstChild, r)
			}); err != nil {
				lockedFprintf(os.Stderr, "sync: %s: %v\n", sPath, err)
				return fmt.Errorf("sync: %s: %w", sPath, err)
			}
			if !quiet {
				lockedPrintf("Copied %s -> %s\n", srcChild, dstChild)
			}
			return nil
		})
		if syncProgress != nil {
			syncProgress.Finish()
		}
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
	if bbbfs.IsAz(parentPath) {
		var totalSize int64
		var count int
		var anyListed bool
		if err := bbbfs.ListStream(ctx, parentPath, func(entry bbbfs.Entry) error {
			anyListed = true
			name := entry.Name
			if name == "" || strings.HasSuffix(name, "/") {
				return nil // skip directories
			}
			if pattern != "" {
				matched, mErr := path.Match(pattern, name)
				if mErr != nil {
					return mErr
				}
				if !matched {
					return nil
				}
			}
			fullpath := strings.TrimSuffix(entry.Path, "/")
			mod := "-" // Placeholder, modtime not available
			display := fullpath
			if relFlag {
				display = strings.TrimSuffix(name, "/")
			}
			if machine {
				fmt.Printf("f\t%d\t%s\t%s\n", entry.Size, mod, display)
			} else {
				fmt.Printf("%10s  %s  %s\n", formatSize(entry.Size), mod, display)
			}
			totalSize += entry.Size
			count++
			return nil
		}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		// If listing returned no entries at all and no wildcard was used, the target
		// may be a single blob. Fall back to Stat so that single-file
		// paths (e.g. az://account/container/blob) are shown.
		if !anyListed && pattern == "" {
			st, statErr := fs.Stat(ctx, parentPath)
			if statErr == nil && !st.IsDir {
				display := target
				if relFlag {
					display = bbbfs.BaseName(parentPath)
				}
				if machine {
					fmt.Printf("f\t%d\t%s\t%s\n", st.Size, "-", display)
				} else {
					fmt.Printf("%10s  %s  %s\n", formatSize(st.Size), "-", display)
				}
				totalSize = st.Size
				count = 1
			}
		}
		if !machine {
			noun := "files"
			if count == 1 {
				noun = "file"
			}
			fmt.Printf("Listed %d %s summing to %s (%d bytes)\n", count, noun, formatSize(totalSize), totalSize)
		}
		return nil
	}
	list, listErr := fs.List(ctx, parentPath)
	if listErr != nil {
		// List may fail on file targets (e.g. ENOTDIR for local paths).
		// Fall back to Stat when no wildcard was used.
		if pattern == "" {
			st, statErr := fs.Stat(ctx, parentPath)
			if statErr == nil && !st.IsDir {
				list = []bbbfs.Entry{st}
			} else {
				fmt.Fprintln(os.Stderr, listErr)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, listErr)
			os.Exit(1)
		}
	}
	// If listing returns nothing and no wildcard was used, the target
	// may be a file rather than a directory. Fall back to Stat so that
	// single-file paths are shown.
	if len(list) == 0 && pattern == "" {
		st, statErr := fs.Stat(ctx, parentPath)
		if statErr == nil && !st.IsDir {
			list = []bbbfs.Entry{st}
		}
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
			fmt.Printf("%10s  %s  %s\n", formatSize(entry.Size), mod, display)
		}
		totalSize += entry.Size
		count++
	}
	if !machine {
		noun := "files"
		if count == 1 {
			noun = "file"
		}
		fmt.Printf("Listed %d %s summing to %s (%d bytes)\n", count, noun, formatSize(totalSize), totalSize)
	}
	return nil
}
