package cgroup

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// GetCgroupID returns the kernel cgroup v2 ID for the given cgroup path.
// This is the same value that bpf_get_current_cgroup_id() returns in BPF
// programs, allowing BPF-side container attribution.
//
// Uses name_to_handle_at(2) to extract the kernfs file handle (type 254),
// whose first 8 bytes are the cgroup ID.
func GetCgroupID(path string) (uint64, error) {
	type fileHandle struct {
		HandleBytes uint32
		HandleType  int32
		FHandle     [128]byte
	}
	var fh fileHandle
	fh.HandleBytes = 128 // buffer size we provide
	var mountID int32

	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return 0, err
	}
	const atFdcwd = ^uintptr(100 + 1) // AT_FDCWD = -100
	_, _, errno := syscall.Syscall6(
		303, // SYS_NAME_TO_HANDLE_AT on x86_64
		atFdcwd,
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&fh)),
		uintptr(unsafe.Pointer(&mountID)),
		0, 0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("name_to_handle_at %s: %w", path, errno)
	}
	if fh.HandleBytes < 8 {
		return 0, fmt.Errorf("handle too short: %d bytes", fh.HandleBytes)
	}
	return binary.LittleEndian.Uint64(fh.FHandle[:8]), nil
}
