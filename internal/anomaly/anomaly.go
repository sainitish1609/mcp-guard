// Package anomaly watches the stream of tool calls for runaway or exfiltration-
// like behavior: an agent (or a compromised one) firing tool calls far faster
// than a human would, or reading an unusual burst of distinct files. It is a
// behavioral layer on top of the per-call path/secret checks.
//
// The detector is intentionally cheap and lock-guarded so it can run inline on
// every request from the client→server pump.
package anomaly

import (
	"fmt"
	"sync"
	"time"
)

// window is the sliding interval over which call rate is measured.
const window = time.Minute

// readBurstWindow and readBurstThreshold define a shorter-horizon warning for a
// sudden spike of distinct file reads (a classic bulk-exfiltration signature).
const (
	readBurstWindow    = 10 * time.Second
	readBurstThreshold = 25
)

// Detector tracks recent activity. The zero value is not usable; call New.
type Detector struct {
	mu        sync.Mutex
	limit     int // hard rate limit (calls/min); 0 disables blocking
	now       func() time.Time
	callTimes []time.Time
	readTimes []time.Time
	warned    map[string]bool // de-dupes repeated warnings of the same kind
}

// New builds a Detector. rateLimit is the calls-per-minute hard cap (0 = no
// blocking, warnings only).
func New(rateLimit int) *Detector {
	return &Detector{limit: rateLimit, now: time.Now, warned: map[string]bool{}}
}

// Observe records a tool call and returns any warning text plus whether the call
// should be blocked (only when a hard rate limit is set and exceeded). isRead
// indicates the call is a read/fetch, feeding the read-burst signal.
func (d *Detector) Observe(isRead bool) (warn string, block bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	t := d.now()
	d.callTimes = trim(append(d.callTimes, t), t.Add(-window))
	rate := len(d.callTimes)

	if isRead {
		d.readTimes = trim(append(d.readTimes, t), t.Add(-readBurstWindow))
		if len(d.readTimes) == readBurstThreshold {
			warn = fmt.Sprintf("read burst: %d reads in %s (possible bulk exfiltration)", len(d.readTimes), readBurstWindow)
		}
	}

	if d.limit > 0 && rate > d.limit {
		return fmt.Sprintf("rate limit exceeded: %d calls/min > %d", rate, d.limit), true
	}

	// Soft warning at 80% of the limit, emitted once.
	if warn == "" && d.limit > 0 && rate >= (d.limit*8)/10 && !d.warned["near-limit"] {
		d.warned["near-limit"] = true
		warn = fmt.Sprintf("approaching rate limit: %d calls/min (cap %d)", rate, d.limit)
	}
	return warn, false
}

// trim drops timestamps at or before cutoff, keeping the slice bounded.
func trim(ts []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(ts) && !ts[i].After(cutoff) {
		i++
	}
	return ts[i:]
}
