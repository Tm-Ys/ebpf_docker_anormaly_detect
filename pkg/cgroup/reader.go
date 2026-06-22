// Package cgroup reads cgroup v2 resource stats for a container: CPU usage
// and throttling, memory pressure and OOM, IO throughput. No eBPF needed —
// these come straight from /sys/fs/cgroup under the container's scope dir.
//
// These signals complement the eBPF collectors: eBPF tells us *what a process
// is doing* (syscalls, sockets, CPU time); cgroup tells us *how the kernel is
// throttling the container as a whole* (CPU throttle %, memory pressure).
// Together they feed the anomaly detector's feature vector.
package cgroup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultCgroupRoot is where cgroupv2 is mounted on virtually every modern host.
const DefaultCgroupRoot = "/sys/fs/cgroup"

// CPUStat mirrors /sys/fs/cgroup/<cg>/cpu.stat.
type CPUStat struct {
	UsageUsec     uint64 // total CPU time used (user+system) in microseconds
	UserUsec      uint64
	SystemUsec    uint64
	NrPeriods     uint64 // scheduler periods elapsed
	NrThrottled   uint64 // periods the cgroup was throttled
	ThrottledUsec uint64 // time spent throttled
}

// PressureLine is one row of a PSI file (some/full).
type PressureLine struct {
	Avg10  float64
	Avg60  float64
	Avg300 float64
	Total  uint64
}

// Pressure holds the "some" and "full" lines of a PSI file.
type Pressure struct {
	Some PressureLine
	Full PressureLine
}

// MemoryStat combines memory.current, memory.max and memory.pressure.
type MemoryStat struct {
	Current  uint64   // bytes currently used
	Max      uint64   // limit in bytes (0 = unlimited)
	OOMKill  uint64   // count of OOM kills (from memory.events)
	Pressure Pressure // memory.pressure
}

// IOStat is the aggregated IO across all devices in the cgroup.
type IOStat struct {
	RBytes uint64
	WBytes uint64
	RIOS   uint64
	WIOS   uint64
}

// Stats is the full cgroup-v2 snapshot for one container.
type Stats struct {
	CPU          CPUStat
	CPUPressure  Pressure // cpu.pressure
	Memory       MemoryStat
	IO           IOStat
}

// Reader resolves a container's cgroup v2 path and reads its stats.
type Reader struct {
	root string // /sys/fs/cgroup
}

// NewReader builds a Reader bound to the given cgroup v2 mount root.
func NewReader(root string) *Reader {
	if root == "" {
		root = DefaultCgroupRoot
	}
	return &Reader{root: root}
}

// PathForContainer returns the cgroup v2 directory for a docker container.
// We assume the systemd layout that OpenCloudOS / RHEL / most distros use:
//   /sys/fs/cgroup/system.slice/docker-<cid>.scope
// Falls back to scanning /proc/<initPid>/cgroup if the assumed path is missing
// (non-systemd dockerd, or a future layout change).
func (r *Reader) PathForContainer(cid string, initPid int) (string, error) {
	// Fast path: systemd convention.
	systemd := filepath.Join(r.root, "system.slice", "docker-"+cid+".scope")
	if _, err := os.Stat(systemd); err == nil {
		return systemd, nil
	}
	// Fall back to reading /proc/<pid>/cgroup for the container init pid.
	if initPid > 0 {
		raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", initPid))
		if err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				// cgroup v2: "0::/path/to/cgroup"
				idx := strings.Index(line, "::")
				if idx < 0 {
					continue
				}
				rel := strings.TrimSpace(line[idx+2:])
				if strings.Contains(rel, cid) {
					return filepath.Join(r.root, rel), nil
				}
			}
		}
	}
	return "", errors.New("cgroup path not found for container " + cid[:min(12, len(cid))])
}

// Read returns a full stats snapshot for the container at the given cgroup path.
func (r *Reader) Read(cgPath string) (*Stats, error) {
	if _, err := os.Stat(cgPath); err != nil {
		return nil, fmt.Errorf("cgroup path missing: %w", err)
	}
	s := &Stats{}
	s.CPU = readCPUStat(filepath.Join(cgPath, "cpu.stat"))
	s.CPUPressure, _ = readPressure(filepath.Join(cgPath, "cpu.pressure"))
	s.Memory = readMemory(cgPath)
	s.IO = readIOStat(filepath.Join(cgPath, "io.stat"))
	return s, nil
}

// --- parsers ---

func readCPUStat(path string) CPUStat {
	var s CPUStat
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) != 2 {
			continue
		}
		n, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "usage_usec":
			s.UsageUsec = n
		case "user_usec":
			s.UserUsec = n
		case "system_usec":
			s.SystemUsec = n
		case "nr_periods":
			s.NrPeriods = n
		case "nr_throttled":
			s.NrThrottled = n
		case "throttled_usec":
			s.ThrottledUsec = n
		}
	}
	return s
}

// readPressure parses a cgroup v2 PSI file.
// Format:
//   some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//   full avg10=0.00 avg60=0.00 avg300=0.00 total=0
func readPressure(path string) (Pressure, error) {
	var p Pressure
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		var linePtr *PressureLine
		switch {
		case strings.HasPrefix(line, "some"):
			linePtr = &p.Some
		case strings.HasPrefix(line, "full"):
			linePtr = &p.Full
		default:
			continue
		}
		for _, kv := range strings.Fields(line)[1:] {
			eq := strings.Index(kv, "=")
			if eq < 0 {
				continue
			}
			k, v := kv[:eq], kv[eq+1:]
			switch k {
			case "avg10":
				linePtr.Avg10, _ = strconv.ParseFloat(v, 64)
			case "avg60":
				linePtr.Avg60, _ = strconv.ParseFloat(v, 64)
			case "avg300":
				linePtr.Avg300, _ = strconv.ParseFloat(v, 64)
			case "total":
				linePtr.Total, _ = strconv.ParseUint(v, 10, 64)
			}
		}
	}
	return p, nil
}

func readMemory(cgPath string) MemoryStat {
	var m MemoryStat
	if b, err := os.ReadFile(filepath.Join(cgPath, "memory.current")); err == nil {
		m.Current, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	if b, err := os.ReadFile(filepath.Join(cgPath, "memory.max")); err == nil {
		t := strings.TrimSpace(string(b))
		if t != "max" {
			m.Max, _ = strconv.ParseUint(t, 10, 64)
		}
	}
	m.Pressure, _ = readPressure(filepath.Join(cgPath, "memory.pressure"))
	// memory.events holds oom/oom_kill counters.
	if f, err := os.Open(filepath.Join(cgPath, "memory.events")); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) == 2 && fields[0] == "oom_kill" {
				m.OOMKill, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
		f.Close()
	}
	return m
}

// readIOStat parses /sys/fs/cgroup/<cg>/io.stat. One line per device:
//   8:0 rbytes=12345 wbytes=67890 rios=100 wios=200
// We aggregate across all devices.
func readIOStat(path string) IOStat {
	var s IOStat
	f, err := os.Open(path)
	if err != nil {
		return s
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		for _, kv := range fields[1:] {
			eq := strings.Index(kv, "=")
			if eq < 0 {
				continue
			}
			k, v := kv[:eq], kv[eq+1:]
			n, _ := strconv.ParseUint(v, 10, 64)
			switch k {
			case "rbytes":
				s.RBytes += n
			case "wbytes":
				s.WBytes += n
			case "rios":
				s.RIOS += n
			case "wios":
				s.WIOS += n
			}
		}
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
