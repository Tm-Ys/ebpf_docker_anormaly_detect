package container

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UPID is a process identity that survives PID recycling: PID + start_time_ticks.
// start_time_ticks is field 22 of /proc/<pid>/stat (clock ticks since boot).
// This mirrors Pixie's upid_t (src/stirling/upid/upid.h:34) but node-local.
type UPID struct {
	PID       uint32
	StartTime uint64
}

// Info is everything we know about a running container.
type Info struct {
	ID        string    // full 64-char container id
	ShortID   string    // first 12 chars, human-friendly
	Name      string    // e.g. "/napcat"
	Image     string    // image:tag
	State     string    // running / exited / ...
	Pid       int       // container init pid (PID 1 in container ns)
	StartedAt time.Time // when the container started
}

// Resolver maps host PIDs to their owning Docker container, with caching.
// It is the spine of the anomaly detector: every eBPF event carries a pid,
// and we need to attribute it to a container.
type Resolver struct {
	docker *DockerClient

	mu         sync.RWMutex
	containers map[string]*Info // cid -> Info
	upidCache  map[UPID]string  // upid -> cid (negative results cached as "")
	// pidSet is a fast lookup: pid -> cid, rebuilt from cgroup.procs on each
	// Refresh. ResolveFast() uses this (O(1) map hit) instead of reading
	// /proc/<pid>/cgroup per pid (which is expensive under high process churn).
	pidSet     map[uint32]string
	cacheTTL   time.Duration
	lastRefresh time.Time
}

// NewResolver builds a Resolver bound to the default docker socket.
func NewResolver(socket string) *Resolver {
	return &Resolver{
		docker:     NewDockerClient(socket),
		containers: make(map[string]*Info),
		upidCache:  make(map[UPID]string),
		cacheTTL:   5 * time.Minute,
	}
}

// Refresh re-enumerates containers from the Docker daemon. Safe to call
// periodically (e.g. every 30s); also evicts stale upidCache entries.
func (r *Resolver) Refresh(ctx context.Context) error {
	summaries, err := r.docker.ListContainers(ctx)
	if err != nil {
		return fmt.Errorf("list containers: %w", err)
	}

	next := make(map[string]*Info, len(summaries))
	for _, s := range summaries {
		detail, derr := r.docker.InspectContainer(ctx, s.ID)
		if derr != nil {
			continue // container may have died between calls
		}
		name := ""
		if len(s.Names) > 0 {
			name = strings.TrimPrefix(s.Names[0], "/")
		}
		startedAt, _ := time.Parse(time.RFC3339Nano, detail.State.StartedAt)
		next[s.ID] = &Info{
			ID:        s.ID,
			ShortID:   s.ID[:12],
			Name:      name,
			Image:     s.Image,
			State:     detail.State.Status,
			Pid:       detail.State.Pid,
			StartedAt: startedAt,
		}
	}

	r.mu.Lock()
	r.containers = next
	r.lastRefresh = time.Now()
	// Rebuild the fast pid->cid lookup from cgroup.procs (one file read per
	// container, not per pid). This is the key performance optimization: the
	// eBPF collectors iterate thousands of pids per poll, and reading
	// /proc/<pid>/cgroup for each was the bottleneck (22% CPU under load).
	pidSet := make(map[uint32]string, 256)
	for cid, info := range next {
		for _, pid := range readCgroupProcs(cid) {
			pidSet[pid] = cid
		}
		_ = info
	}
	r.pidSet = pidSet
	// Drop cache entries whose container no longer exists.
	for u, cid := range r.upidCache {
		if cid != "" {
			if _, ok := next[cid]; !ok {
				delete(r.upidCache, u)
			}
		}
	}
	r.mu.Unlock()
	return nil
}

// Containers returns a snapshot of known containers.
func (r *Resolver) Containers() map[string]*Info {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]*Info, len(r.containers))
	for k, v := range r.containers {
		out[k] = v
	}
	return out
}

// ContainerByID returns metadata for a known cid, or nil.
func (r *Resolver) ContainerByID(cid string) *Info {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.containers[cid]
}

// Resolve maps a host pid to a container id (full 64-char). Returns ("", false)
// for host processes or unknown pids. Cached by UPID so PID reuse is safe.
func (r *Resolver) Resolve(pid uint32) (string, bool) {
	start, err := readStartTimeTicks(pid)
	if err != nil {
		return "", false
	}
	upid := UPID{PID: pid, StartTime: start}

	r.mu.RLock()
	cid, ok := r.upidCache[upid]
	r.mu.RUnlock()
	if ok {
		return cid, cid != ""
	}

	// Cache miss: parse /proc/<pid>/cgroup.
	cid = parseContainerIDFromCgroup(pid)
	// NOTE: we intentionally do NOT check if cid is in r.containers here.
	// The container may have started after the last Refresh but before the
	// next one — its cid is valid (from cgroup) even if not yet in our cache.
	// The known-check was causing 100% data loss for short-lived attack
	// containers that start/exit between Refresh cycles.

	r.mu.Lock()
	r.upidCache[upid] = cid
	r.mu.Unlock()
	return cid, cid != ""
}

// ClearCache forces the next Resolve() to re-read /proc.
// Call after Refresh() if you want stale mappings dropped immediately.
func (r *Resolver) ClearCache() {
	r.mu.Lock()
	r.upidCache = make(map[UPID]string)
	r.mu.Unlock()
}

// ResolveFast is an O(1) lookup using the pidSet built during Refresh.
// Use this in hot paths (eBPF collector polls) instead of Resolve().
// Returns "" for host processes and unknown pids — no /proc reads.
func (r *Resolver) ResolveFast(pid uint32) string {
	r.mu.RLock()
	cid := r.pidSet[pid]
	r.mu.RUnlock()
	return cid
}

// readCgroupProcs reads /sys/fs/cgroup/.../docker-<cid>.scope/cgroup.procs
// and returns all PIDs in that container. One file read per container.
func readCgroupProcs(cid string) []uint32 {
	for _, pattern := range []string{
		filepath.Join("/sys/fs/cgroup/system.slice", "docker-"+cid+".scope"),
		filepath.Join("/sys/fs/cgroup", "docker", cid),
	} {
		procsPath := filepath.Join(pattern, "cgroup.procs")
		data, err := os.ReadFile(procsPath)
		if err != nil {
			continue
		}
		var pids []uint32
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if pid, err := strconv.ParseUint(line, 10, 32); err == nil {
				pids = append(pids, uint32(pid))
			}
		}
		return pids
	}
	return nil
}

// --- /proc parsing helpers ---

// dockerCIDRe matches the container id substring in cgroup v2 paths.
// Handles systemd and legacy layouts:
//   /system.slice/docker-<cid>.scope        (systemd, what OpenCloudOS uses)
//   /docker/<cid>                            (legacy cgroupfs)
//   /system.slice/containerd-<cid>.scope    (containerd via systemd)
//   /kubepods.slice/...docker-<cid>.scope   (k8s, we still match & extract)
var dockerCIDRe = regexp.MustCompile(`(?:docker|containerd)[/-]([0-9a-f]{64})`)

// parseContainerIDFromCgroup reads /proc/<pid>/cgroup and extracts the cid.
func parseContainerIDFromCgroup(pid uint32) string {
	f, err := os.Open(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "cgroup"))
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup v2: single line "0::/path". v1: multi-line "subsys:path".
		// We don't care which; just scan for the cid pattern.
		if m := dockerCIDRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

// readStartTimeTicks returns field 22 of /proc/<pid>/stat (starttime in clock ticks).
// Field 2 (comm) may contain spaces and parens, so we parse from the last ')'.
func readStartTimeTicks(pid uint32) (uint64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "stat"))
	if err != nil {
		return 0, err
	}
	// Find last ')' to skip the comm field which can contain spaces.
	rparen := strings.LastIndexByte(string(data), ')')
	if rparen < 0 || rparen+1 >= len(data) {
		return 0, errors.New("stat: malformed")
	}
	fields := strings.Fields(string(data[rparen+1:]))
	// After ')', the next field is #3. starttime is field #22, so it's fields[22-3]=fields[19].
	if len(fields) <= 19 {
		return 0, errors.New("stat: too few fields")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}
