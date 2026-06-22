// Package feature aggregates raw collector outputs into per-container feature
// vectors over fixed time windows. A FeatureVector is the unit the anomaly
// detector (P5) consumes: one row of ~35 numeric features describing a
// container's behavior in the window.
//
// Design:
//   - The Aggregator owns N per-cid accumulators + one for host.
//   - Each collector pushes its output to the Aggregator via typed methods.
//   - On every window tick, each accumulator finalizes into a FeatureVector
//     and is reset. Zero-activity containers still emit (with all-zero deltas)
//     so the model sees their steady state.
package feature

import (
	"sync"
	"time"

	"github.com/anomaly/container-anomaly/pkg/collector/pidruntime"
	"github.com/anomaly/container-anomaly/pkg/collector/syscalls"
	"github.com/anomaly/container-anomaly/pkg/collector/tcpstats"
	"github.com/anomaly/container-anomaly/pkg/cgroup"
)

// Vector is one container's behavior in one window. Field order matters: it
// matches the CSV header in Encoder so the ML pipeline can stay column-stable.
type Vector struct {
	WindowStart time.Time
	WindowEnd   time.Time

	// Identity
	ContainerID string // "" = host aggregate
	Name        string
	Image       string

	// Process lifecycle
	ProcExits   uint64 // thread-group-leader exits
	ProcCrashes uint64 // exits with signal != 0

	// Network
	TCPBytesTx   uint64
	TCPBytesRx   uint64
	TCPRetrans   uint64

	// CPU (eBPF, per-pid runtime summed)
	CPURuntimeNS uint64

	// Syscall histogram (deltas over the window)
	SysTotal         uint64
	SysFileOpen      uint64
	SysFileClose     uint64
	SysFileRead      uint64
	SysFileWrite     uint64
	SysFileUnlink    uint64
	SysFileRename    uint64
	SysFilePerm      uint64
	SysNetSocket     uint64
	SysNetConnect    uint64
	SysNetBind       uint64
	SysNetListen     uint64
	SysNetAccept     uint64
	SysNetSend       uint64
	SysNetRecv       uint64
	SysProcExec      uint64
	SysProcFork      uint64
	SysProcKill      uint64
	SysPrivEscalate  uint64
	SysEscapeAttempt uint64
	SysMemLayout     uint64
	SysOther         uint64

	// Cgroup v2 (deltas where applicable; pressure/current are point-in-time)
	CgroupCPUUsageMS    uint64  // cpu.stat usage_usec delta / 1000
	CgroupCPUThrottlePct float64 // nr_throttled / nr_periods over the window
	CgroupMemCurrentMB  uint64  // memory.current at window end
	CgroupMemPressure   float64 // memory.pressure some avg10
	CgroupOOMKills      uint64  // memory.events oom_kill delta
	CgroupIOReadMB      uint64  // io.stat rbytes delta
	CgroupIOWriteMB     uint64  // io.stat wbytes delta
}

// per-cid rolling accumulator. Fields that are deltas get zeroed each window;
// fields that are cumulative (cgroup counters) are tracked as previous totals.
type accumulator struct {
	v Vector

	// previous cgroup cumulative counters (for delta math)
	prevCPUUsageUsec uint64
	prevIORead       uint64
	prevIOWrite      uint64
}

// Aggregator collects raw events/snapshots and emits Vectors every Window.
type Aggregator struct {
	mu      sync.Mutex
	window  time.Duration
	acc     map[string]*accumulator // key: cid ("" = host)
	cgroup  *cgroup.Reader
	out     chan Vector
	stopCh  chan struct{}
	// ResolveName fills in the container name for cids that IngestCgroup hasn't
	// seen yet (short-lived containers that start/exit between cgroup polls).
	ResolveName func(cid string) (name, image string)
}

// New builds an Aggregator that emits a Vector per known container + host
// every window. cgroupReader may be nil (cgroup fields stay zero).
func New(window time.Duration, cg *cgroup.Reader, bufferSize int) *Aggregator {
	if bufferSize <= 0 {
		bufferSize = 64
	}
	return &Aggregator{
		window: window,
		acc:    make(map[string]*accumulator),
		cgroup: cg,
		out:    make(chan Vector, bufferSize),
		stopCh: make(chan struct{}),
	}
}

// Vectors returns the channel of finalized feature vectors.
func (a *Aggregator) Vectors() <-chan Vector { return a.out }

// Stop drains the loop. Safe to call once.
func (a *Aggregator) Stop() { close(a.stopCh) }

// accFor returns the accumulator for a cid, creating it if missing.
func (a *Aggregator) accFor(cid string) *accumulator {
	ac := a.acc[cid]
	if ac == nil {
		ac = &accumulator{}
		a.acc[cid] = ac
	}
	return ac
}

// --- ingest methods (called from the agent's collector fan-in) ---

// IngestExit records one process exit event.
func (a *Aggregator) IngestExit(containerID string, crash bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ac := a.accFor(containerID)
	ac.v.ProcExits++
	if crash {
		ac.v.ProcCrashes++
	}
}

// IngestTCP merges a tcp snapshot into per-cid accumulators.
func (a *Aggregator) IngestTCP(snap tcpstats.Snapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, row := range snap.Rows {
		ac := a.accFor(row.ContainerID)
		ac.v.TCPBytesTx += row.BytesTx
		ac.v.TCPBytesRx += row.BytesRx
		ac.v.TCPRetrans += row.Retransmits
	}
}

// IngestCPU merges a pid_runtime snapshot.
func (a *Aggregator) IngestCPU(snap pidruntime.Snapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, row := range snap.Rows {
		ac := a.accFor(row.ContainerID)
		ac.v.CPURuntimeNS += row.RuntimeNS
	}
}

// IngestSyscalls merges a syscall histogram snapshot.
func (a *Aggregator) IngestSyscalls(snap syscalls.Snapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, row := range snap.Rows {
		ac := a.accFor(row.ContainerID)
		c := row.Counts
		ac.v.SysTotal += c.Total
		ac.v.SysFileOpen += c.FileOpen
		ac.v.SysFileClose += c.FileClose
		ac.v.SysFileRead += c.FileRead
		ac.v.SysFileWrite += c.FileWrite
		ac.v.SysFileUnlink += c.FileUnlink
		ac.v.SysFileRename += c.FileRename
		ac.v.SysFilePerm += c.FilePerm
		ac.v.SysNetSocket += c.NetSocket
		ac.v.SysNetConnect += c.NetConnect
		ac.v.SysNetBind += c.NetBind
		ac.v.SysNetListen += c.NetListen
		ac.v.SysNetAccept += c.NetAccept
		ac.v.SysNetSend += c.NetSend
		ac.v.SysNetRecv += c.NetRecv
		ac.v.SysProcExec += c.ProcExec
		ac.v.SysProcFork += c.ProcFork
		ac.v.SysProcKill += c.ProcKill
		ac.v.SysPrivEscalate += c.PrivEscalate
		ac.v.SysEscapeAttempt += c.EscapeAttempt
		ac.v.SysMemLayout += c.MemLayout
		ac.v.SysOther += c.Other
	}
}

// IngestCgroup records cgroup stats for a container. Called by the agent's
// cgroup poller. Computes deltas vs the previous sample.
func (a *Aggregator) IngestCgroup(cid, name, image string, s *cgroup.Stats) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ac := a.accFor(cid)
	ac.v.Name = name
	ac.v.Image = image

	// CPU usage delta
	if s.CPU.UsageUsec >= ac.prevCPUUsageUsec {
		ac.v.CgroupCPUUsageMS = (s.CPU.UsageUsec - ac.prevCPUUsageUsec) / 1000
	}
	ac.prevCPUUsageUsec = s.CPU.UsageUsec

	// Throttle ratio over the delta'd periods. Approximation: use cumulative
	// nr_periods/nr_throttled diff if available; else fall back to the raw ratio.
	if s.CPU.NrPeriods > 0 {
		ac.v.CgroupCPUThrottlePct = float64(s.CPU.NrThrottled) / float64(s.CPU.NrPeriods) * 100
	}

	// Memory: point-in-time current, pressure avg10.
	ac.v.CgroupMemCurrentMB = s.Memory.Current / 1024 / 1024
	ac.v.CgroupMemPressure = s.Memory.Pressure.Some.Avg10
	ac.v.CgroupOOMKills = s.Memory.OOMKill // cumulative; delta handled by model if needed

	// IO deltas
	if s.IO.RBytes >= ac.prevIORead {
		ac.v.CgroupIOReadMB = (s.IO.RBytes - ac.prevIORead) / 1024 / 1024
	}
	ac.prevIORead = s.IO.RBytes
	if s.IO.WBytes >= ac.prevIOWrite {
		ac.v.CgroupIOWriteMB = (s.IO.WBytes - ac.prevIOWrite) / 1024 / 1024
	}
	ac.prevIOWrite = s.IO.WBytes
}

// Run ticks the window loop. On each tick, every known accumulator finalizes
// into a Vector (even all-zero ones — the model needs to see steady state),
// emits it, and resets delta fields.
func (a *Aggregator) Run() {
	t := time.NewTicker(a.window)
	defer t.Stop()
	var windowStart time.Time
	for {
		select {
		case <-a.stopCh:
			return
		case end := <-t.C:
			if windowStart.IsZero() {
				windowStart = end.Add(-a.window)
			}
			a.mu.Lock()
			out := make([]Vector, 0, len(a.acc))
			for cid, ac := range a.acc {
				v := ac.v
				v.WindowStart = windowStart
				v.WindowEnd = end
				v.ContainerID = cid
				// Backfill name/image for cids that IngestCgroup hasn't seen
				// (e.g. short-lived attack containers). Without this, their
				// CSV rows have empty name → grouped as "host" → invisible to
				// the per-container detection report.
				if cid != "" && v.Name == "" && a.ResolveName != nil {
					name, image := a.ResolveName(cid)
					v.Name = name
					v.Image = image
					ac.v.Name = name
					ac.v.Image = image
				}
				out = append(out, v)
				// Reset delta fields for the next window. Cgroup "previous"
				// counters are kept so delta math stays continuous.
				ac.v = Vector{Name: v.Name, Image: v.Image}
			}
			a.mu.Unlock()
			windowStart = end
			for _, v := range out {
				select {
				case a.out <- v:
				case <-a.stopCh:
					return
				}
			}
		}
	}
}
