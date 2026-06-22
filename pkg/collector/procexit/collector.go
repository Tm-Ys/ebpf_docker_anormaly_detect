// Package procexit wraps the proc_exit BPF program. It streams process-exit
// events from a perf buffer to a Go channel, attributing each to a container
// via the supplied PID resolver.
package procexit

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Event is a decoded process exit. ContainerID is "" if the pid could not be
// attributed (host process, or container already gone).
type Event struct {
	Ts          uint64 // bpf_ktime_get_ns (kernel boot time)
	StartTime   uint64 // task->start_boottime (ns since boot)
	Tgid        uint32 // host pid
	ExitCode    uint32 // raw; low 7 bits = signal, bits 8+ = status
	Comm        string
	ContainerID string // full 64-char cid, or ""
}

// Signal extracts the killing signal from the raw exit_code (0 if none).
func (e Event) Signal() int { return int(e.ExitCode & 0x7f) }

// Status extracts the exit status from the raw exit_code (0 if killed).
func (e Event) Status() int { return int(e.ExitCode >> 8) & 0xff }

// Collector owns the BPF objects, the tracepoint link, and the perf reader.
type Collector struct {
	objs procexitObjects
	link link.Link
	rd   *perf.Reader

	stopCh chan struct{}
	wg     sync.WaitGroup

	// ResolvePID maps a host pid to a container id (or "" if host/unknown).
	// Injected so this collector stays decoupled from the container package.
	ResolvePID func(uint32) string

	events chan Event
}

// New loads the BPF program, attaches the sched_process_exit tracepoint,
// and opens the perf buffer reader.
func New(resolve func(uint32) string) (*Collector, error) {
	if resolve == nil {
		return nil, errors.New("procexit: resolve callback is required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	var c Collector
	if err := loadProcexitObjects(&c.objs, nil); err != nil {
		return nil, fmt.Errorf("load proc_exit objects: %w", err)
	}

	tp, err := link.Tracepoint("sched", "sched_process_exit", c.objs.HandleProcExit, nil)
	if err != nil {
		c.objs.Close()
		return nil, fmt.Errorf("attach sched_process_exit: %w", err)
	}
	c.link = tp

	// 256 KiB per CPU; enough to absorb bursts. Bump if you see lost events.
	rd, err := perf.NewReader(c.objs.ProcExitEvents, 256*1024)
	if err != nil {
		tp.Close()
		c.objs.Close()
		return nil, fmt.Errorf("perf reader: %w", err)
	}
	c.rd = rd
	c.ResolvePID = resolve
	c.stopCh = make(chan struct{})
	c.events = make(chan Event, 1024)
	return &c, nil
}

// Events returns the channel of decoded exit events. Closed when Stop returns.
func (c *Collector) Events() <-chan Event { return c.events }

// Start spawns the goroutine that drains the perf buffer.
func (c *Collector) Start() {
	c.wg.Add(1)
	go c.run()
}

// Stop closes the perf reader and waits for the drain goroutine.
func (c *Collector) Stop() {
	close(c.stopCh)
	c.rd.Close() // unblocks Read()
	c.wg.Wait()
	c.link.Close()
	c.objs.Close()
	close(c.events)
}

func (c *Collector) run() {
	defer c.wg.Done()
	eventSize := int(unsafe.Sizeof(procexitProcExitEvent{}))
	for {
		record, err := c.rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			continue
		}
		if record.LostSamples > 0 {
			// Drop notification only; production would emit a counter.
			continue
		}
		if len(record.RawSample) < eventSize {
			continue
		}
		// Reinterpret the sample bytes as the generated struct. The layout
		// is guaranteed by bpf2go to match the C declaration in the .bpf.c.
		raw := *(*procexitProcExitEvent)(unsafe.Pointer(&record.RawSample[0]))
		ev := Event{
			Ts:        raw.TsNs,
			StartTime: raw.StartTimeNs,
			Tgid:      raw.Tgid,
			ExitCode:  raw.ExitCode,
			Comm:      trimNull(raw.Comm[:]),
		}
		ev.ContainerID = c.ResolvePID(ev.Tgid)
		// Skip host process exits — anomaly detection only cares about
		// containers. This filter cuts >90% of events under high process
		// churn (find/sha256sum spawning thousands of short-lived procs).
		if ev.ContainerID == "" {
			continue
		}
		select {
		case c.events <- ev:
		case <-c.stopCh:
			return
		}
	}
}

// trimNull strips trailing NUL bytes from a fixed-size char array.
// bpf2go renders C 'char' as Go int8, hence the signed element type.
func trimNull(b []int8) string {
	var sb []byte
	for _, c := range b {
		if c == 0 {
			break
		}
		sb = append(sb, byte(c))
	}
	return string(sb)
}
