package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	outputMu        sync.Mutex
	activeBars      []*progressBar // guarded by outputMu; rendered in order
	maxLabelWidth   int            // guarded by outputMu; high-water mark for label alignment
	elapsedTickerMu sync.Mutex
	elapsedTicker   *time.Ticker
	elapsedDone     chan struct{}
	elapsedWg       sync.WaitGroup
)

// startElapsedTicker starts a 1-second background ticker that re-renders
// active progress bars so the elapsed-time field stays up-to-date even when
// no new progress events arrive. It is safe to call multiple times; only
// one ticker runs at a time. Requires outputMu NOT to be held.
func startElapsedTicker() {
	elapsedTickerMu.Lock()
	defer elapsedTickerMu.Unlock()
	if elapsedTicker != nil {
		return // already running
	}
	elapsedTicker = time.NewTicker(1 * time.Second)
	elapsedDone = make(chan struct{})
	// Capture the current ticker and done channel so the goroutine does not
	// depend on the mutable package-level pointers.
	t := elapsedTicker
	done := elapsedDone
	elapsedWg.Add(1)
	go func() {
		defer elapsedWg.Done()
		for {
			select {
			case <-done:
				return
			case _, ok := <-t.C:
				if !ok {
					return
				}
				outputMu.Lock()
				if len(activeBars) > 0 {
					clearActiveBars()
					rerenderActiveBars()
				}
				outputMu.Unlock()
			}
		}
	}()
}

// stopElapsedTicker stops the background ticker and waits for the
// goroutine to exit. Safe to call when no ticker is running.
func stopElapsedTicker() {
	elapsedTickerMu.Lock()
	if elapsedTicker == nil {
		elapsedTickerMu.Unlock()
		return
	}
	elapsedTicker.Stop()
	close(elapsedDone)
	elapsedTicker = nil
	elapsedDone = nil
	elapsedTickerMu.Unlock()
	elapsedWg.Wait()
}

func clearActiveBars() {
	n := len(activeBars)
	if n == 0 || !isTerminal(os.Stderr) {
		return
	}
	if n > 1 {
		fmt.Fprintf(os.Stderr, "\033[%dA", n-1) // move cursor up to first bar line
	}
	fmt.Fprintf(os.Stderr, "\r\033[J") // clear from cursor to end of screen
}

func rerenderActiveBars() {
	for i, bar := range activeBars {
		bar.renderAligned(maxLabelWidth)
		if i < len(activeBars)-1 {
			fmt.Fprintf(os.Stderr, "\n")
		}
	}
}

func addActiveBar(p *progressBar) {
	for _, b := range activeBars {
		if b == p {
			return
		}
	}
	if n := len(p.label); n > maxLabelWidth {
		maxLabelWidth = n
	}
	if p.pinBottom {
		activeBars = append(activeBars, p)
		return
	}
	// Insert before any pinBottom bars so they stay at the bottom.
	insertAt := len(activeBars)
	for insertAt > 0 && activeBars[insertAt-1].pinBottom {
		insertAt--
	}
	activeBars = append(activeBars, nil)
	copy(activeBars[insertAt+1:], activeBars[insertAt:])
	activeBars[insertAt] = p
}

func removeActiveBar(p *progressBar) {
	for i, b := range activeBars {
		if b == p {
			activeBars = append(activeBars[:i], activeBars[i+1:]...)
			return
		}
	}
}

func lockedPrintf(format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBars()
	fmt.Printf(format, args...)
	rerenderActiveBars()
}

func lockedPrintln(args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBars()
	fmt.Println(args...)
	rerenderActiveBars()
}

func lockedFprintf(w io.Writer, format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBars()
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	rerenderActiveBars()
}

// barAwareHandler wraps an slog.Handler so log output coordinates with the
// pinned progress bar. It clears the active bar before writing and
// re-renders it after, preventing log lines from clobbering the bar.
type barAwareHandler struct {
	inner slog.Handler
}

func (h *barAwareHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

func (h *barAwareHandler) Handle(ctx context.Context, r slog.Record) error {
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBars()
	err := h.inner.Handle(ctx, r)
	rerenderActiveBars()
	return err
}

func (h *barAwareHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &barAwareHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h *barAwareHandler) WithGroup(name string) slog.Handler {
	return &barAwareHandler{inner: h.inner.WithGroup(name)}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

type progressBar struct {
	label      string
	width      int
	showSpeed  bool
	byteSized  bool // if true, show done/total as formatted byte sizes
	startedAt  time.Time
	total      atomic.Int64
	done       atomic.Int64
	bytesDone  atomic.Int64
	lastDone   atomic.Int64
	lastTotal  atomic.Int64
	finished   atomic.Bool
	pinBottom  bool         // if true, renders at the bottom of the bar stack
	lastRender atomic.Int64 // unix nanos of last actual render; for throttling
}

const (
	progressUninitialized = int64(-1)
	renderMinInterval     = 500 * time.Millisecond // throttle renders from parallel goroutines

	ansiReset = "\033[0m"
	ansiBold  = "\033[1m"
	ansiGreen = "\033[32m"
	ansiCyan  = "\033[36m"
	ansiGray  = "\033[90m"
	ansiClear = "\033[K"
)

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
	startElapsedTicker()
	bar.render(0)
	return bar
}

// newStreamingProgressBar creates a progress bar with total=0 for streaming
// mode where the total grows dynamically as items are discovered. The bar
// stays invisible until the first SetTotal call with a positive value.
func newStreamingProgressBar(label string, quiet bool, showSpeed bool) *progressBar {
	if quiet || !isTerminal(os.Stderr) {
		return nil
	}
	bar := &progressBar{
		label:     label,
		width:     28,
		showSpeed: showSpeed,
		startedAt: time.Now(),
	}
	bar.lastDone.Store(progressUninitialized)
	bar.lastTotal.Store(progressUninitialized)
	startElapsedTicker()
	// total starts at 0; bar won't render until SetTotal(>0) is called.
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

// atomicMax updates an atomic.Int64 to val if val is greater than the current
// value. It is safe for concurrent use.
func atomicMax(a *atomic.Int64, val int64) {
	for {
		cur := a.Load()
		if val <= cur {
			return
		}
		if a.CompareAndSwap(cur, val) {
			return
		}
	}
}

func (p *progressBar) SetTotal(total int64) {
	if p == nil {
		return
	}
	if total < 1 {
		total = 1
	}
	// Monotonically increasing: only allow total to grow, never shrink.
	for {
		cur := p.total.Load()
		if total <= cur {
			return
		}
		if p.total.CompareAndSwap(cur, total) {
			break
		}
	}
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
	// If the bar was never actually rendered (e.g. a 0-byte copy where
	// total was never set, or a streaming bar that never received
	// SetTotal), skip the final render and trailing newline to avoid
	// printing a misleading "1 B/1 B" line.
	neverShown := p.lastTotal.Load() == progressUninitialized
	total := p.total.Load()
	if total < 1 {
		total = 1
		p.total.Store(total)
	}
	p.done.Store(total)
	outputMu.Lock()
	clearActiveBars()
	removeActiveBar(p)
	if !neverShown {
		// Use the global high-water mark for label width so the completed
		// line aligns with all bars that have ever been shown.
		p.renderAligned(maxLabelWidth)
		fmt.Fprintf(os.Stderr, "\n")
	}
	rerenderActiveBars()
	noActiveBars := len(activeBars) == 0
	outputMu.Unlock()
	if noActiveBars {
		stopElapsedTicker()
	}
}

// renderAligned writes the progress bar to stderr with the label padded to
// labelWidth characters. This aligns bars with different-length labels.
// outputMu must be held.
func (p *progressBar) renderAligned(labelWidth int) {
	if p == nil {
		return
	}
	done := p.done.Load()
	total := p.total.Load()
	if total <= 0 {
		return
	}
	done, total = clampProgress(done, total)
	elapsedDur := time.Since(p.startedAt)
	elapsed := elapsedDur.Seconds()
	speed := 0.0
	if p.showSpeed && elapsed > 0 {
		speed = float64(p.bytesDone.Load()) / elapsed
	}
	label := p.label
	if labelWidth > len(label) {
		label = label + strings.Repeat(" ", labelWidth-len(label))
	}
	if isTerminal(os.Stderr) {
		line := formatFancyBar(label, done, total, p.width, speed, p.showSpeed, p.byteSized, elapsedDur)
		fmt.Fprintf(os.Stderr, "\r"+ansiClear+"%s", line)
	} else {
		line := formatProgressBar(label, done, total, p.width, speed, p.showSpeed, p.byteSized, elapsedDur)
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
	if p == nil || p.finished.Load() {
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
	// Throttle: skip rendering if another render happened within renderMinInterval.
	// This prevents parallel goroutines from flooding the terminal with ANSI escapes.
	now := time.Now().UnixNano()
	last := p.lastRender.Load()
	if now-last < int64(renderMinInterval) {
		return
	}
	if !p.lastRender.CompareAndSwap(last, now) {
		return // another goroutine won the race
	}
	outputMu.Lock()
	defer outputMu.Unlock()
	clearActiveBars()
	addActiveBar(p)
	rerenderActiveBars()
}

func formatProgressBar(label string, done, total int64, width int, speed float64, showSpeed bool, byteSized bool, elapsed time.Duration) string {
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
	elapsedStr := formatElapsed(elapsed)
	switch {
	case byteSized && showSpeed:
		return fmt.Sprintf("%s [%s] %3d%% (%s/%s, %s) %s", label, bar, percent, formatSize(done), formatSize(total), formatByteSpeed(speed), elapsedStr)
	case byteSized:
		return fmt.Sprintf("%s [%s] %3d%% (%s/%s) %s", label, bar, percent, formatSize(done), formatSize(total), elapsedStr)
	case showSpeed:
		return fmt.Sprintf("%s [%s] %3d%% (%d/%d, %s) %s", label, bar, percent, done, total, formatByteSpeed(speed), elapsedStr)
	default:
		return fmt.Sprintf("%s [%s] %3d%% (%d/%d) %s", label, bar, percent, done, total, elapsedStr)
	}
}

func formatFancyBar(label string, done, total int64, width int, speed float64, showSpeed bool, byteSized bool, elapsed time.Duration) string {
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
	elapsedStr := formatElapsed(elapsed)
	switch {
	case byteSized && showSpeed:
		return fmt.Sprintf(ansiBold+"%s"+ansiReset+" %s %s%3d%%"+ansiReset+" (%s/%s, %s) %s%s", label, bar, pctColor, percent, formatSize(done), formatSize(total), formatByteSpeed(speed), elapsedStr, suffix)
	case byteSized:
		return fmt.Sprintf(ansiBold+"%s"+ansiReset+" %s %s%3d%%"+ansiReset+" (%s/%s) %s%s", label, bar, pctColor, percent, formatSize(done), formatSize(total), elapsedStr, suffix)
	case showSpeed:
		return fmt.Sprintf(ansiBold+"%s"+ansiReset+" %s %s%3d%%"+ansiReset+" (%d/%d, %s) %s%s", label, bar, pctColor, percent, done, total, formatByteSpeed(speed), elapsedStr, suffix)
	default:
		return fmt.Sprintf(ansiBold+"%s"+ansiReset+" %s %s%3d%%"+ansiReset+" (%d/%d) %s%s", label, bar, pctColor, percent, done, total, elapsedStr, suffix)
	}
}

func formatSize(bytes int64) string {
	if bytes < 0 {
		bytes = 0
	}
	const (
		kib int64 = 1024
		mib       = 1024 * kib
		gib       = 1024 * mib
		tib       = 1024 * gib
	)
	// formatUnit formats bytes in terms of the given unit using integer
	// arithmetic (no float64 conversion) and truncates to 1 decimal place.
	formatUnit := func(b, unit int64, suffix string) string {
		whole := b / unit
		frac := (b % unit) * 10 / unit // truncated tenths
		return fmt.Sprintf("%d.%d %s", whole, frac, suffix)
	}
	switch {
	case bytes >= tib:
		return formatUnit(bytes, tib, "TiB")
	case bytes >= gib:
		return formatUnit(bytes, gib, "GiB")
	case bytes >= mib:
		return formatUnit(bytes, mib, "MiB")
	case bytes >= kib:
		return formatUnit(bytes, kib, "KiB")
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func formatByteSpeed(bytesPerSecond float64) string {
	if bytesPerSecond < 0 {
		bytesPerSecond = 0
	}
	const (
		kb = 1024.0
		mb = 1024.0 * kb
		gb = 1024.0 * mb
	)
	switch {
	case bytesPerSecond >= gb:
		return fmt.Sprintf("%.1f GB/s", bytesPerSecond/gb)
	case bytesPerSecond >= mb:
		return fmt.Sprintf("%.1f MB/s", bytesPerSecond/mb)
	case bytesPerSecond >= kb:
		return fmt.Sprintf("%.1f KB/s", bytesPerSecond/kb)
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSecond)
	}
}

func formatElapsed(d time.Duration) string {
	d = d.Truncate(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
