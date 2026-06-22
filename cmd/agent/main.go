// agent: container anomaly collector with BPF-side container attribution.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/anomaly/container-anomaly/pkg/collector/pidruntime"
	"github.com/anomaly/container-anomaly/pkg/collector/procexit"
	"github.com/anomaly/container-anomaly/pkg/collector/syscalls"
	"github.com/anomaly/container-anomaly/pkg/collector/tcpstats"
	"github.com/anomaly/container-anomaly/pkg/container"
	"github.com/anomaly/container-anomaly/pkg/cgroup"
	"github.com/anomaly/container-anomaly/pkg/feature"
)

func main() {
	socket := flag.String("socket", container.DefaultDockerSocket, "docker daemon socket")
	refresh := flag.Duration("refresh", 10*time.Second, "container list refresh")
	window := flag.Duration("window", 30*time.Second, "feature vector window")
	outDir := flag.String("out", "data", "output directory for feature CSV")
	tickTCP := flag.Duration("tcp-tick", 10*time.Second, "tcp stats poll")
	tickCPU := flag.Duration("cpu-tick", 10*time.Second, "cpu runtime poll")
	tickSys := flag.Duration("sys-tick", 5*time.Second, "syscall histogram poll")
	tickCG := flag.Duration("cg-tick", 10*time.Second, "cgroup stats poll")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("mkdir out: %v", err)
	}
	csvPath := filepath.Join(*outDir, "features.csv")
	enc, err := feature.NewEncoder(csvPath)
	if err != nil {
		log.Fatalf("open csv: %v", err)
	}
	defer enc.Close()
	log.Printf("writing feature vectors to %s", csvPath)

	// --- Container resolver + cgroup reader ---
	r := container.NewResolver(*socket)
	if err := r.Refresh(context.Background()); err != nil {
		log.Fatalf("container refresh: %v", err)
	}
	cgReader := cgroup.NewReader(cgroup.DefaultCgroupRoot)

	resolve := func(pid uint32) string {
		cid, _ := r.Resolve(pid)
		return cid
	}

	// --- Collectors ---
	pec, err := procexit.New(resolve)
	if err != nil { log.Fatalf("procexit: %v", err) }
	defer pec.Stop()
	pec.Start()

	tsc, err := tcpstats.New(resolve, *tickTCP)
	if err != nil { log.Fatalf("tcpstats: %v", err) }
	defer tsc.Stop()
	tsc.Start()

	prc, err := pidruntime.New(resolve, *tickCPU)
	if err != nil { log.Fatalf("pidruntime: %v", err) }
	defer prc.Stop()
	prc.Start()

	scc, err := syscalls.New(*tickSys)
	if err != nil { log.Fatalf("syscalls: %v", err) }
	defer scc.Stop()
	scc.Start()

	// --- Container mapping for BPF syscall attribution ---
	// Each container gets a stable index. The BPF cgid_map maps
	// cgroup_id → index, and syscalls_by_cgid is keyed by index.
	var nextIdx uint32
	idxByCid := map[string]uint32{}

	updateMappings := func() {
		var mappings []syscalls.ContainerMapping
		for cid, info := range r.Containers() {
			cgPath, err := cgReader.PathForContainer(cid, info.Pid)
			if err != nil { continue }
			cgid, err := cgroup.GetCgroupID(cgPath)
			if err != nil { continue }
			idx, ok := idxByCid[cid]
			if !ok {
				idx = nextIdx
				nextIdx++
				idxByCid[cid] = idx
			}
			mappings = append(mappings, syscalls.ContainerMapping{
				CgroupID: cgid, Index: idx, CID: cid,
			})
		}
		if len(mappings) > 0 {
			if err := scc.UpdateContainers(mappings); err != nil {
				log.Printf("syscall mapping: %v", err)
			}
		}
	}
	updateMappings() // initial

	// Single refresh goroutine: docker refresh + syscall mapping update.
	go func() {
		t := time.NewTicker(*refresh)
		defer t.Stop()
		for range t.C {
			if err := r.Refresh(context.Background()); err != nil {
				log.Printf("container refresh: %v", err)
				continue
			}
			updateMappings()
		}
	}()

	// --- Feature aggregator ---
	agg := feature.New(*window, cgReader, 256)
	agg.ResolveName = func(cid string) (string, string) {
		if c := r.ContainerByID(cid); c != nil {
			return c.Name, c.Image
		}
		if len(cid) >= 12 {
			return "cid:" + cid[:12], ""
		}
		return "unknown", ""
	}
	go agg.Run()
	defer agg.Stop()

	go pollCgroup(cgReader, r, agg, *tickCG)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	log.Printf("agent up: window=%s out=%s. Ctrl-C to stop.", *window, csvPath)

	for {
		select {
		case <-stop:
			log.Printf("shutting down.")
			return
		case ev := <-pec.Events():
			agg.IngestExit(ev.ContainerID, ev.Signal() != 0)
		case snap := <-tsc.Snapshots():
			agg.IngestTCP(snap)
		case snap := <-prc.Snapshots():
			agg.IngestCPU(snap)
		case snap := <-scc.Snapshots():
			agg.IngestSyscalls(snap)
		case v := <-agg.Vectors():
			if err := enc.Write(v); err != nil {
				log.Printf("csv write: %v", err)
			}
		}
	}
}

func pollCgroup(cg *cgroup.Reader, r *container.Resolver, agg *feature.Aggregator, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for range t.C {
		for cid, c := range r.Containers() {
			path, err := cg.PathForContainer(cid, c.Pid)
			if err != nil { continue }
			s, err := cg.Read(path)
			if err != nil { continue }
			agg.IngestCgroup(cid, c.Name, c.Image, s)
		}
	}
}
