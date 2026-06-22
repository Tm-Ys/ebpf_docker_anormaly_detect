// Package syscalls wraps the syscall_trace BPF program with BPF-side container
// attribution via cgroup IDs. The BPF program uses bpf_get_current_cgroup_id()
// to identify containers at syscall time — no userspace /proc resolution needed.
package syscalls

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Counts is the delta histogram for one container in one poll window.
type Counts struct {
	Total         uint64
	FileOpen      uint64
	FileClose     uint64
	FileRead      uint64
	FileWrite     uint64
	FileUnlink    uint64
	FileRename    uint64
	FilePerm      uint64
	NetSocket     uint64
	NetConnect    uint64
	NetBind       uint64
	NetListen     uint64
	NetAccept     uint64
	NetSend       uint64
	NetRecv       uint64
	ProcExec      uint64
	ProcFork      uint64
	ProcKill      uint64
	PrivEscalate  uint64
	EscapeAttempt uint64
	MemLayout     uint64
	Other         uint64
}

// Row pairs a container's histogram delta with its cid.
type Row struct {
	ContainerID string
	Counts      Counts
}

// Snapshot is the set of histogram deltas for one poll window.
type Snapshot struct {
	At   time.Time
	Rows []Row
}

// ContainerMapping tells the BPF program which cgroup belongs to which container.
// The agent builds this from docker + cgroup filesystem.
type ContainerMapping struct {
	CgroupID uint64 // kernel cgroup v2 id
	Index    uint32 // assigned slot (0, 1, 2, ...)
	CID      string // docker container id
}

// Collector owns the BPF objects and manages cgroup→container attribution.
type Collector struct {
	objs syscallsObjects
	link link.Link

	tick   time.Duration
	tops   chan Snapshot
	stopCh chan struct{}
	wg     sync.WaitGroup

	mu       sync.Mutex
	idxToCid   map[uint32]string            // container index → cid (userspace)
	prevSeen   map[uint32]syscallsSyscallCounts // monotonic totals per index
}

// New loads the BPF program and attaches raw_tracepoint/sys_enter.
func New(tick time.Duration) (*Collector, error) {
	if tick <= 0 {
		return nil, errors.New("syscalls: tick must be positive")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var c Collector
	if err := loadSyscallsObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load syscall_trace: %w", err)
	}

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: c.objs.TraceSysEnter,
	})
	if err != nil {
		c.objs.Close()
		return nil, fmt.Errorf("attach raw_tracepoint sys_enter: %w", err)
	}
	c.link = l
	c.tick = tick
	c.tops = make(chan Snapshot, 16)
	c.stopCh = make(chan struct{})
	c.idxToCid = make(map[uint32]string)
	c.prevSeen = make(map[uint32]syscallsSyscallCounts)
	return &c, nil
}

// UpdateContainers syncs the BPF cgid_map with the current container set.
// Called by the agent on each docker refresh. Adds new containers, removes
// stale ones. This is the ONLY userspace interaction with container attribution.
func (c *Collector) UpdateContainers(mappings []ContainerMapping) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Build the new set of valid cgid → index entries.
	newIdx := make(map[uint32]string, len(mappings))
	for _, m := range mappings {
		// Write to BPF map: cgid → index.
		if err := c.objs.CgidMap.Put(m.CgroupID, m.Index); err != nil {
			return fmt.Errorf("cgid_map put %d: %w", m.CgroupID, err)
		}
		newIdx[m.Index] = m.CID
	}

	// Remove stale entries from BPF cgid_map (containers that no longer exist).
	// We iterate the current map and delete entries whose index isn't in newIdx.
	var key uint64
	var val uint32
	iter := c.objs.CgidMap.Iterate()
	for iter.Next(&key, &val) {
		if _, ok := newIdx[val]; !ok {
			_ = c.objs.CgidMap.Delete(key)
		}
	}

	// Update userspace index→cid map.
	c.idxToCid = newIdx
	return nil
}

func (c *Collector) Snapshots() <-chan Snapshot { return c.tops }

func (c *Collector) Start() {
	c.wg.Add(1)
	go c.run()
}

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

// pollOnce reads the per-container histogram from syscalls_by_cgid, computes
// deltas, and maps container indices to cids. No /proc reads — all attribution
// was done in BPF at syscall time.
func (c *Collector) pollOnce(now time.Time) Snapshot {
	snap := Snapshot{At: now}
	current := make(map[uint32]syscallsSyscallCounts)

	var key uint32
	var perCPU []syscallsSyscallCounts
	iter := c.objs.SyscallsByCgid.Iterate()
	for iter.Next(&key, &perCPU) {
		var sum syscallsSyscallCounts
		for _, v := range perCPU {
			sum.Total += v.Total
			sum.FileOpen += v.FileOpen
			sum.FileClose += v.FileClose
			sum.FileRead += v.FileRead
			sum.FileWrite += v.FileWrite
			sum.FileUnlink += v.FileUnlink
			sum.FileRename += v.FileRename
			sum.FilePerm += v.FilePerm
			sum.NetSocket += v.NetSocket
			sum.NetConnect += v.NetConnect
			sum.NetBind += v.NetBind
			sum.NetListen += v.NetListen
			sum.NetAccept += v.NetAccept
			sum.NetSend += v.NetSend
			sum.NetRecv += v.NetRecv
			sum.ProcExec += v.ProcExec
			sum.ProcFork += v.ProcFork
			sum.ProcKill += v.ProcKill
			sum.PrivEscalate += v.PrivEscalate
			sum.EscapeAttempt += v.EscapeAttempt
			sum.MemLayout += v.MemLayout
			sum.Other += v.Other
		}
		current[key] = sum
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict dead container indices.
	for idx := range c.prevSeen {
		if _, ok := current[idx]; !ok {
			delete(c.prevSeen, idx)
		}
	}

	snap.Rows = make([]Row, 0, len(current))
	for idx, total := range current {
		prev := c.prevSeen[idx]
		c.prevSeen[idx] = total
		delta := subtract(total, prev)
		if delta.Total == 0 {
			continue
		}
		cid := c.idxToCid[idx]
		snap.Rows = append(snap.Rows, Row{
			ContainerID: cid,
			Counts:      delta,
		})
	}
	return snap
}

func subtract(total, prev syscallsSyscallCounts) Counts {
	return Counts{
		Total:         safe(total.Total, prev.Total),
		FileOpen:      safe(total.FileOpen, prev.FileOpen),
		FileClose:     safe(total.FileClose, prev.FileClose),
		FileRead:      safe(total.FileRead, prev.FileRead),
		FileWrite:     safe(total.FileWrite, prev.FileWrite),
		FileUnlink:    safe(total.FileUnlink, prev.FileUnlink),
		FileRename:    safe(total.FileRename, prev.FileRename),
		FilePerm:      safe(total.FilePerm, prev.FilePerm),
		NetSocket:     safe(total.NetSocket, prev.NetSocket),
		NetConnect:    safe(total.NetConnect, prev.NetConnect),
		NetBind:       safe(total.NetBind, prev.NetBind),
		NetListen:     safe(total.NetListen, prev.NetListen),
		NetAccept:     safe(total.NetAccept, prev.NetAccept),
		NetSend:       safe(total.NetSend, prev.NetSend),
		NetRecv:       safe(total.NetRecv, prev.NetRecv),
		ProcExec:      safe(total.ProcExec, prev.ProcExec),
		ProcFork:      safe(total.ProcFork, prev.ProcFork),
		ProcKill:      safe(total.ProcKill, prev.ProcKill),
		PrivEscalate:  safe(total.PrivEscalate, prev.PrivEscalate),
		EscapeAttempt: safe(total.EscapeAttempt, prev.EscapeAttempt),
		MemLayout:     safe(total.MemLayout, prev.MemLayout),
		Other:         safe(total.Other, prev.Other),
	}
}

func safe(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return 0
}
