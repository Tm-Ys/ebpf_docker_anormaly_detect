package feature

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
)

// Headers defines the CSV column order. Keep in sync with Vector field order
// and the numericFeatures slice used by the ML pipeline.
var Headers = []string{
	"window_start", "window_end",
	"container_id", "name", "image",
	"proc_exits", "proc_crashes",
	"tcp_bytes_tx", "tcp_bytes_rx", "tcp_retrans",
	"cpu_runtime_ns",
	"sys_total", "sys_file_open", "sys_file_close", "sys_file_read", "sys_file_write",
	"sys_file_unlink", "sys_file_rename", "sys_file_perm",
	"sys_net_socket", "sys_net_connect", "sys_net_bind", "sys_net_listen", "sys_net_accept",
	"sys_net_send", "sys_net_recv",
	"sys_proc_exec", "sys_proc_fork", "sys_proc_kill",
	"sys_priv_escalate", "sys_escape_attempt", "sys_mem_layout", "sys_other",
	"cg_cpu_usage_ms", "cg_cpu_throttle_pct", "cg_mem_current_mb",
	"cg_mem_pressure", "cg_oom_kills", "cg_io_read_mb", "cg_io_write_mb",
}

// NumericFeatureIndices are the column indices (into Headers) of features the
// IsolationForest model should train on. Excludes identity + timestamp columns.
var NumericFeatureIndices = func() []int {
	skip := map[string]bool{
		"window_start": true, "window_end": true,
		"container_id": true, "name": true, "image": true,
	}
	out := make([]int, 0, len(Headers))
	for i, h := range Headers {
		if !skip[h] {
			out = append(out, i)
		}
	}
	return out
}()

// Encoder writes Vectors as CSV rows to a file. Header is written once.
type Encoder struct {
	mu     sync.Mutex
	w      *csv.Writer
	f      *os.File
	header bool
}

// NewEncoder opens path for appending and writes the header if the file is new.
func NewEncoder(path string) (*Encoder, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	// If the file doesn't exist yet, we'll write the header.
	_, err := os.Stat(path)
	newFile := os.IsNotExist(err)
	f, err := os.OpenFile(path, flags, 0644)
	if err != nil {
		return nil, err
	}
	e := &Encoder{w: csv.NewWriter(f), f: f, header: !newFile}
	if newFile {
		if err := e.w.Write(Headers); err != nil {
			f.Close()
			return nil, err
		}
		e.header = true
		e.w.Flush()
	}
	return e, nil
}

// Write appends one vector row.
func (e *Encoder) Write(v Vector) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	row := []string{
		v.WindowStart.Format("2006-01-02T15:04:05"),
		v.WindowEnd.Format("2006-01-02T15:04:05"),
		v.ContainerID,
		v.Name,
		v.Image,
		utoa(v.ProcExits),
		utoa(v.ProcCrashes),
		utoa(v.TCPBytesTx),
		utoa(v.TCPBytesRx),
		utoa(v.TCPRetrans),
		utoa(v.CPURuntimeNS),
		utoa(v.SysTotal),
		utoa(v.SysFileOpen),
		utoa(v.SysFileClose),
		utoa(v.SysFileRead),
		utoa(v.SysFileWrite),
		utoa(v.SysFileUnlink),
		utoa(v.SysFileRename),
		utoa(v.SysFilePerm),
		utoa(v.SysNetSocket),
		utoa(v.SysNetConnect),
		utoa(v.SysNetBind),
		utoa(v.SysNetListen),
		utoa(v.SysNetAccept),
		utoa(v.SysNetSend),
		utoa(v.SysNetRecv),
		utoa(v.SysProcExec),
		utoa(v.SysProcFork),
		utoa(v.SysProcKill),
		utoa(v.SysPrivEscalate),
		utoa(v.SysEscapeAttempt),
		utoa(v.SysMemLayout),
		utoa(v.SysOther),
		utoa(v.CgroupCPUUsageMS),
		ftoa(v.CgroupCPUThrottlePct),
		utoa(v.CgroupMemCurrentMB),
		ftoa(v.CgroupMemPressure),
		utoa(v.CgroupOOMKills),
		utoa(v.CgroupIOReadMB),
		utoa(v.CgroupIOWriteMB),
	}
	if err := e.w.Write(row); err != nil {
		return err
	}
	e.w.Flush()
	return e.w.Error()
}

// Close flushes and closes the underlying file.
func (e *Encoder) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.w.Flush()
	return e.f.Close()
}

// WriteAllHeaderTo writes just the header to a writer (for splitting train/test).
func WriteHeaderTo(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(Headers); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

func utoa(n uint64) string { return strconv.FormatUint(n, 10) }
func ftoa(f float64) string {
	if f == 0 {
		return "0"
	}
	return fmt.Sprintf("%.4f", f)
}
