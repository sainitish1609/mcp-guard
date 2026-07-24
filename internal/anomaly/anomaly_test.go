package anomaly

import (
	"testing"
	"time"
)

// withClock swaps in a controllable clock for deterministic tests.
func withClock(d *Detector, t *time.Time) {
	d.now = func() time.Time { return *t }
}

func TestRateLimitBlocks(t *testing.T) {
	d := New(10)
	clock := time.Now()
	withClock(d, &clock)
	blocked := false
	for i := 0; i < 12; i++ {
		if _, b := d.Observe(false); b {
			blocked = true
		}
	}
	if !blocked {
		t.Fatal("expected block once calls exceed the per-minute limit")
	}
}

func TestRateLimitWindowSlides(t *testing.T) {
	d := New(10)
	clock := time.Now()
	withClock(d, &clock)
	for i := 0; i < 10; i++ {
		d.Observe(false)
	}
	// Advance beyond the window; old calls should age out and not block.
	clock = clock.Add(2 * time.Minute)
	if _, b := d.Observe(false); b {
		t.Fatal("calls outside the window must not count toward the limit")
	}
}

func TestReadBurstWarns(t *testing.T) {
	d := New(0) // no hard limit; warnings only
	clock := time.Now()
	withClock(d, &clock)
	var lastWarn string
	for i := 0; i < readBurstThreshold; i++ {
		w, _ := d.Observe(true)
		if w != "" {
			lastWarn = w
		}
	}
	if lastWarn == "" {
		t.Fatal("expected a read-burst warning")
	}
}

func TestNoLimitNeverBlocks(t *testing.T) {
	d := New(0)
	clock := time.Now()
	withClock(d, &clock)
	for i := 0; i < 1000; i++ {
		if _, b := d.Observe(false); b {
			t.Fatal("rateLimit=0 must never block")
		}
	}
}
