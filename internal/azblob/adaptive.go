package azblob

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// adaptiveSem is a counting semaphore whose capacity can be adjusted at
// runtime. Tokens are channel-backed for ctx-aware Acquire; shrink requests
// that cannot be satisfied immediately are recorded as a deficit and absorbed
// by future Release calls (which then return their token to the void instead
// of back to the pool).
type adaptiveSem struct {
	mu       sync.Mutex
	tokens   chan struct{}
	capacity int
	deficit  int // tokens owed (Release will consume instead of return)
}

func newAdaptiveSem(initial, maxCap int) *adaptiveSem {
	if initial < 1 {
		initial = 1
	}
	if maxCap < initial {
		maxCap = initial
	}
	s := &adaptiveSem{
		tokens:   make(chan struct{}, maxCap),
		capacity: initial,
	}
	for i := 0; i < initial; i++ {
		s.tokens <- struct{}{}
	}
	return s
}

func (s *adaptiveSem) Acquire(ctx context.Context) error {
	select {
	case <-s.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *adaptiveSem) Release() {
	s.mu.Lock()
	if s.deficit > 0 {
		s.deficit--
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.tokens <- struct{}{}
}

func (s *adaptiveSem) SetCapacity(n int) {
	if n < 1 {
		n = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n == s.capacity {
		return
	}
	if n > s.capacity {
		extra := n - s.capacity
		if cap(s.tokens) < n {
			// Channel was sized to the original max; we cap growth there.
			extra = cap(s.tokens) - len(s.tokens) - s.deficit
			if extra < 0 {
				extra = 0
			}
		}
		added := 0
		for i := 0; i < extra; i++ {
			select {
			case s.tokens <- struct{}{}:
				added++
			default:
				// channel full; stop growing further
				i = extra
			}
		}
		s.capacity += added
		return
	}
	// shrink
	drop := s.capacity - n
	for drop > 0 {
		select {
		case <-s.tokens:
			drop--
		default:
			s.deficit += drop
			drop = 0
		}
	}
	s.capacity = n
}

func (s *adaptiveSem) Capacity() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.capacity
}

// adaptiveControllerConfig configures the throughput-driven concurrency
// controller. The controller samples a cumulative bytes counter at Interval
// and grows the sem capacity while throughput improves by at least Hysteresis,
// holds while it plateaus, and shrinks once it regresses by Hysteresis.
type adaptiveControllerConfig struct {
	Min        int
	Max        int
	Step       int
	Interval   time.Duration
	Hysteresis float64 // e.g. 0.05 = 5%
	LogTag     string  // for slog.Debug
}

// runAdaptiveController drives sem.SetCapacity based on the rate of change of
// the bytes counter. It returns when ctx is canceled or done is closed.
func runAdaptiveController(ctx context.Context, sem *adaptiveSem, bytes *atomic.Int64, cfg adaptiveControllerConfig, done <-chan struct{}) {
	if cfg.Interval <= 0 {
		cfg.Interval = 750 * time.Millisecond
	}
	if cfg.Step < 1 {
		cfg.Step = 4
	}
	if cfg.Hysteresis <= 0 {
		cfg.Hysteresis = 0.05
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	lastBytes := bytes.Load()
	lastTime := time.Now()
	var lastTput float64
	plateau := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case now := <-ticker.C:
			cur := bytes.Load()
			dt := now.Sub(lastTime).Seconds()
			if dt <= 0 {
				continue
			}
			tput := float64(cur-lastBytes) / dt
			lastBytes = cur
			lastTime = now
			curCap := sem.Capacity()
			if lastTput == 0 {
				// First sample: try one growth step to start exploring.
				if curCap < cfg.Max {
					sem.SetCapacity(min(curCap+cfg.Step, cfg.Max))
				}
				lastTput = tput
				continue
			}
			improvement := (tput - lastTput) / lastTput
			switch {
			case improvement > cfg.Hysteresis && curCap < cfg.Max:
				sem.SetCapacity(min(curCap+cfg.Step, cfg.Max))
				plateau = 0
			case improvement < -cfg.Hysteresis && curCap > cfg.Min:
				sem.SetCapacity(max(curCap-cfg.Step, cfg.Min))
				plateau = 0
			default:
				plateau++
				// Periodically probe up to confirm we've found the peak.
				if plateau >= 3 && curCap < cfg.Max {
					sem.SetCapacity(min(curCap+cfg.Step, cfg.Max))
					plateau = 0
				}
			}
			slog.Debug("adaptive concurrency",
				"tag", cfg.LogTag,
				"tput_mb_s", tput/(1024*1024),
				"improvement", improvement,
				"cap", sem.Capacity(),
			)
			lastTput = tput
		}
	}
}

// envMaxConcurrency returns the value of name parsed as a positive integer, or
// fallback when unset/invalid.
func envMaxConcurrency(name string, fallback int) int {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v < 1 {
		return fallback
	}
	return v
}

// adaptiveBounds derives (initial, min, max, step) for the controller from the
// caller-supplied concurrency. The supplied value is treated as the initial
// (and minimum) capacity so existing tuning is preserved; the controller is
// only allowed to grow upward.
func adaptiveBounds(concurrency, hardCap int, envMaxName string) (initial, minC, maxC, step int) {
	if concurrency < 1 {
		concurrency = 1
	}
	initial = concurrency
	minC = concurrency
	// Default ceiling: 4× initial, clamped to hardCap, with a floor so very
	// small initial values still have room to grow.
	maxC = concurrency * 4
	if maxC < 32 {
		maxC = 32
	}
	if maxC > hardCap {
		maxC = hardCap
	}
	if envMaxName != "" {
		maxC = envMaxConcurrency(envMaxName, maxC)
	}
	if maxC < minC {
		maxC = minC
	}
	step = concurrency / 4
	if step < 4 {
		step = 4
	}
	if step > maxC-minC {
		step = max(1, maxC-minC)
	}
	return initial, minC, maxC, step
}
