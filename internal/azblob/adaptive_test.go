package azblob

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdaptiveSemGrowAfterShrinkWithDeficit(t *testing.T) {
	sem := newAdaptiveSem(4, 8)
	ctx := context.Background()
	// Take out all 4 tokens.
	for i := 0; i < 4; i++ {
		if err := sem.Acquire(ctx); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	// Shrink while everything is in flight: deficit = 2, capacity = 2.
	sem.SetCapacity(2)
	// Grow back to 6 while deficit is still outstanding. Effective in-flight
	// must never exceed 6 (4 outstanding + at most 2 new tokens), and the
	// deficit must be absorbed by the grow instead of by future Releases.
	sem.SetCapacity(6)
	// Two more slots should now be available without any Release.
	for i := 0; i < 2; i++ {
		ctxT, cancel := context.WithTimeout(ctx, time.Second)
		if err := sem.Acquire(ctxT); err != nil {
			cancel()
			t.Fatalf("acquire-after-grow %d: %v", i, err)
		}
		cancel()
	}
	// At this point 6 tokens are out and capacity is 6. Acquire must block.
	blocked := make(chan struct{})
	go func() {
		_ = sem.Acquire(ctx)
		close(blocked)
	}()
	select {
	case <-blocked:
		t.Fatal("acquire returned past intended cap; deficit not absorbed by grow")
	case <-time.After(50 * time.Millisecond):
	}
	// Release one -> Acquire goroutine should unblock; no token-dropping.
	sem.Release()
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("Acquire did not return after Release")
	}
	// Drain the rest.
	for i := 0; i < 6; i++ {
		sem.Release()
	}
}

func TestAdaptiveSemAcquireRelease(t *testing.T) {
	sem := newAdaptiveSem(2, 4)
	ctx := context.Background()
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("acquire 1: %v", err)
	}
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("acquire 2: %v", err)
	}
	// At capacity now; third Acquire should block until Release.
	done := make(chan struct{})
	go func() {
		_ = sem.Acquire(ctx)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Acquire returned before Release")
	case <-time.After(50 * time.Millisecond):
	}
	sem.Release()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Acquire did not return after Release")
	}
	sem.Release()
}

func TestAdaptiveSemGrow(t *testing.T) {
	sem := newAdaptiveSem(1, 4)
	ctx := context.Background()
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	sem.SetCapacity(3)
	// Two more slots became available.
	for i := 0; i < 2; i++ {
		ctxT, cancel := context.WithTimeout(ctx, time.Second)
		if err := sem.Acquire(ctxT); err != nil {
			cancel()
			t.Fatalf("acquire after grow %d: %v", i, err)
		}
		cancel()
	}
}

func TestAdaptiveSemShrinkDeficit(t *testing.T) {
	sem := newAdaptiveSem(4, 4)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		if err := sem.Acquire(ctx); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	// Shrink while all tokens are out: should record deficit and absorb on Release.
	sem.SetCapacity(2)
	sem.Release() // absorbed by deficit
	sem.Release() // absorbed by deficit
	// Now there are 2 outstanding tokens and capacity 2; further Releases should
	// make tokens available again.
	sem.Release()
	sem.Release()
	ctxT, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := sem.Acquire(ctxT); err != nil {
		t.Fatalf("acquire after shrink+release: %v", err)
	}
}

func TestAdaptiveSemAcquireCtxCancel(t *testing.T) {
	sem := newAdaptiveSem(1, 2)
	ctx := context.Background()
	if err := sem.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := sem.Acquire(cctx); err == nil {
		t.Fatal("expected ctx error on cancelled Acquire")
	}
}

func TestAdaptiveSemConcurrent(t *testing.T) {
	sem := newAdaptiveSem(4, 8)
	ctx := context.Background()
	var inFlight, maxInFlight atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := sem.Acquire(ctx); err != nil {
				return
			}
			cur := inFlight.Add(1)
			for {
				old := maxInFlight.Load()
				if cur <= old || maxInFlight.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(2 * time.Millisecond)
			inFlight.Add(-1)
			sem.Release()
		}()
	}
	wg.Wait()
	if got := maxInFlight.Load(); got > 8 {
		t.Fatalf("max in-flight exceeded capacity: got %d, want <=8", got)
	}
}

func TestRunAdaptiveControllerStops(t *testing.T) {
	sem := newAdaptiveSem(2, 8)
	var staged atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go runAdaptiveController(ctx, sem, &staged, adaptiveControllerConfig{
		Min:        2,
		Max:        8,
		Step:       2,
		Interval:   10 * time.Millisecond,
		Hysteresis: 0.05,
		LogTag:     "test",
	}, done)
	// Simulate steadily improving throughput so the controller grows capacity.
	for i := 0; i < 5; i++ {
		staged.Add(1 << 20)
		time.Sleep(15 * time.Millisecond)
	}
	cancel()
	close(done)
}
