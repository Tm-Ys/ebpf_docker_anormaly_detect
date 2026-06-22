// P1 demo: enumerate containers + attribute host pids to containers.
// Run as root. Press Ctrl-C to stop.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/anomaly/container-anomaly/pkg/container"
)

func main() {
	r := container.NewResolver(container.DefaultDockerSocket)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	// First run immediately.
	if err := r.Refresh(ctx); err != nil {
		log.Fatalf("refresh: %v", err)
	}
	scanOnce(r)

	for {
		select {
		case <-stop:
			log.Println("p1 demo stopped")
			return
		case <-tick.C:
			if err := r.Refresh(ctx); err != nil {
				log.Printf("refresh: %v", err)
				continue
			}
			scanOnce(r)
		}
	}
}

func scanOnce(r *container.Resolver) {
	fmt.Println(strings.Repeat("=", 72))
	fmt.Printf("[scan @ %s]\n", time.Now().Format("15:04:05"))

	// 1. Known containers.
	containers := r.Containers()
	if len(containers) == 0 {
		fmt.Println("  (no containers discovered)")
	} else {
		for _, c := range containers {
			fmt.Printf("  container %-12s name=%-20s state=%-9s pid=%d image=%s\n",
				c.ShortID, c.Name, c.State, c.Pid, c.Image)
		}
	}

	// 2. Walk /proc and attribute each pid.
	perContainer := map[string]int{} // cid -> pid count
	hostCount := 0
	total := 0

	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("read /proc: %v", err)
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		total++
		cid, ok := r.Resolve(uint32(pid))
		if !ok || cid == "" {
			hostCount++
			continue
		}
		perContainer[cid]++
	}

	// 3. Report attribution.
	fmt.Printf("  total pids scanned=%d  host=%d  containerized=%d\n",
		total, hostCount, total-hostCount)
	for cid, n := range perContainer {
		var name string
		if c := r.ContainerByID(cid); c != nil {
			name = c.Name
		}
		fmt.Printf("    -> %-12s (name=%-20s) pids=%d\n", cid[:12], name, n)
	}
}
