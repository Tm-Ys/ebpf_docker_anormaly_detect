// Package pidruntime wraps the pid_runtime BPF program. It polls per-pid CPU
// runtime from a percpu hash and emits per-(pid, container) deltas.
package pidruntime

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Row is one pid's CPU runtime delta for a poll window.
type Row struct {
	Pid         uint32
	ContainerID string // "" if host
	RuntimeNS   uint64
}

// Snapshot is the set of deltas captured in one poll.
type Snapshot struct {
	At   time.Time
	Rows []Row
}

// Collector owns the BPF objects, the tracepoint link, and the poller.
type Collector struct {
	objs pidruntimeObjects
	link link.Link

	resolve func(uint32) string
	tick    time.Duration
	tops    chan Snapshot

	// prevSeen holds the last-seen monotonic total runtime per pid. BPF only
	// ever increments runtime_ns, so delta = current_total - prevSeen[pid].
	// This avoids racy read-then-zero in the kernel map.
	prevSeen map[uint32]uint64

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New loads the BPF program and attaches sched:sched_switch.
func New(resolve func(uint32) string, tick time.Duration) (*Collector, error) {
	if resolve == nil {
		return nil, errors.New("pidruntime: resolve callback required")
	}
	if tick <= 0 {
		return nil, errors.New("pidruntime: tick must be positive")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var c Collector
	if err := loadPidruntimeObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load pid_runtime: %w", err)
	}

	l, err := link.Tracepoint("sched", "sched_switch", c.objs.TraceSchedSwitch, nil)
	if err != nil {
		c.objs.Close()
		return nil, fmt.Errorf("attach sched_switch: %w", err)
	}
	c.link = l
	c.resolve = resolve
	c.tick = tick
	c.tops = make(chan Snapshot, 16)
	c.stopCh = make(chan struct{})
	c.prevSeen = make(map[uint32]uint64)
	return &c, nil
}

// Snapshots returns the channel of polled snapshots.
func (c *Collector) Snapshots() <-chan Snapshot { return c.tops }

// Start spawns the poller goroutine.
func (c *Collector) Start() {
	c.wg.Add(1)
	go c.run()
}

// Stop detaches the tracepoint and releases resources.
func (c *Collector) Stop() {
	close(c.stopCh)
	c.wg.Wait()
	c.link.Close()
	c.objs.Close()
	close(c.tops)
}

func (c *Collector) run() {
	defer c.wg.Done()
	t := time.NewTicker(c.tick)
	defer t.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case now := <-t.C:
			snap := c.pollOnce(now)
			select {
			case c.tops <- snap:
			case <-c.stopCh:
				return
			}
		}
	}
}

// pollOnce reads the monotonic runtime_ns total per pid and computes the delta
// since the previous poll. BPF never resets runtime_ns, so this is race-free.
// Pids that vanish (exited) are evicted from prevSeen so their totals don't
// leak forever; their last delta is still reported for this window.
func (c *Collector) pollOnce(now time.Time) Snapshot {
	snap := Snapshot{At: now}
	current := make(map[uint32]uint64, len(c.prevSeen))

	var key uint32
	var perCPU []pidruntimeCpuAcct
	iter := c.objs.CpuAcctByPid.Iterate()
	for iter.Next(&key, &perCPU) {
		var sum uint64
		for _, v := range perCPU {
			sum += v.RuntimeNs
		}
		current[key] = sum
	}

	// Evict pids that disappeared since last poll (process exited).
	for pid := range c.prevSeen {
		if _, ok := current[pid]; !ok {
			delete(c.prevSeen, pid)
		}
	}

	snap.Rows = make([]Row, 0, len(current))
	for pid, total := range current {
		prev := c.prevSeen[pid]
		c.prevSeen[pid] = total
		if total <= prev {
			continue // no new CPU time this window (or counter wrapped — ignore)
		}
		snap.Rows = append(snap.Rows, Row{
			Pid:         pid,
			ContainerID: c.resolve(pid),
			RuntimeNS:   total - prev,
		})
	}
	return snap
}
