// Package tcpstats wraps the tcp_stats BPF program. It polls per-tgid TCP
// counters from a percpu hash every Tick, attributes them to containers,
// and emits aggregated snapshots on a channel.
package tcpstats

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Stats is the per-(tgid, container) delta for one polling window.
type Stats struct {
	Tgid         uint32
	ContainerID  string // "" if host
	BytesTx      uint64
	BytesRx      uint64
	PktsTx       uint64
	PktsRx       uint64
	Retransmits  uint64
}

// Snapshot is the set of deltas captured in one poll.
type Snapshot struct {
	At     time.Time
	Rows   []Stats
}

// Collector owns the BPF objects, kprobe links, and the poller.
type Collector struct {
	objs  tcpstatsObjects
	links []link.Link

	resolve func(uint32) string
	tick    time.Duration
	tops    chan Snapshot

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// New loads the BPF program and attaches all kprobes.
func New(resolve func(uint32) string, tick time.Duration) (*Collector, error) {
	if resolve == nil {
		return nil, errors.New("tcpstats: resolve callback required")
	}
	if tick <= 0 {
		return nil, errors.New("tcpstats: tick must be positive")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var c Collector
	if err := loadTcpstatsObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load tcp_stats: %w", err)
	}

	// Attach all three probes. Entry probes use link.Kprobe; the return probe
	// on tcp_sendmsg MUST use link.Kretprobe, otherwise PT_REGS_RC reads the
	// entry-time registers (garbage) instead of the return value.
	type probe struct {
		prog    *ebpf.Program
		name    string
		isRet   bool // true = kretprobe (return), false = kprobe (entry)
	}
	probes := []probe{
		{c.objs.KretprobeTcpSendmsg, "tcp_sendmsg", true},
		{c.objs.KprobeTcpCleanupRbuf, "tcp_cleanup_rbuf", false},
		{c.objs.KprobeTcpRetransmitSkb, "tcp_retransmit_skb", false},
	}
	for _, p := range probes {
		var l link.Link
		var err error
		if p.isRet {
			l, err = link.Kretprobe(p.name, p.prog, nil)
		} else {
			l, err = link.Kprobe(p.name, p.prog, nil)
		}
		if err != nil {
			c.cleanup()
			return nil, fmt.Errorf("attach %s %s: %w", probeKind(p.isRet), p.name, err)
		}
		c.links = append(c.links, l)
	}

	c.resolve = resolve
	c.tick = tick
	c.tops = make(chan Snapshot, 16)
	c.stopCh = make(chan struct{})
	return &c, nil
}

// Snapshots returns the channel of polled snapshots. Closed on Stop.
func (c *Collector) Snapshots() <-chan Snapshot { return c.tops }

// Start spawns the poller goroutine.
func (c *Collector) Start() {
	c.wg.Add(1)
	go c.run()
}

// Stop detaches probes and releases resources.
func (c *Collector) Stop() {
	close(c.stopCh)
	c.wg.Wait()
	c.cleanup()
	close(c.tops)
}

func probeKind(isRet bool) string {
	if isRet {
		return "kretprobe"
	}
	return "kprobe"
}

func (c *Collector) cleanup() {
	for _, l := range c.links {
		_ = l.Close()
	}
	c.links = nil
	c.objs.Close()
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

// pollOnce reads-and-clears every entry in the percpu hash, summing per-cpu
// values into a per-tgid delta. Entries are deleted so the next window starts
// from zero. We accept minor racy loss (counts between read+delete) as the
// window is short — anomaly detection is robust to it.
func (c *Collector) pollOnce(now time.Time) Snapshot {
	snap := Snapshot{At: now}
	perTgid := map[uint32]Stats{}

	// For PERCPU maps, MapIterator.Next populates valueOut with a per-CPU slice.
	// Passing nil panics because Next internally Lookups the value to validate.
	var key uint32
	var perCPU []tcpstatsTcpStats
	iter := c.objs.TcpStatsByTgid.Iterate()
	for iter.Next(&key, &perCPU) {
		var sum Stats
		sum.Tgid = key
		for _, v := range perCPU {
			sum.BytesTx += v.BytesTx
			sum.BytesRx += v.BytesRx
			sum.PktsTx += v.PktsTx
			sum.PktsRx += v.PktsRx
			sum.Retransmits += v.Retransmits
		}
		perTgid[key] = sum
		_ = c.objs.TcpStatsByTgid.Delete(key)
	}

	snap.Rows = make([]Stats, 0, len(perTgid))
	for _, s := range perTgid {
		s.ContainerID = c.resolve(s.Tgid)
		snap.Rows = append(snap.Rows, s)
	}
	return snap
}
