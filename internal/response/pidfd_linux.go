//go:build linux

package response

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// nsPerTick converts kernel nanoseconds to the clock ticks used by
// /proc/<pid>/stat. USER_HZ is 100 on every mainstream Linux architecture.
const nsPerTick = 1_000_000_000 / 100

// New returns a Responder that kills through pidfds.
func New(dryRun bool) *Responder {
	return &Responder{DryRun: dryRun, SelfPID: os.Getpid(), kill: pidfdKill}
}

// pidfdKill sends SIGKILL to the process instance identified by pid and
// its kernel start time, without a PID-reuse race:
//
//  1. pidfd_open pins the process currently holding pid.
//  2. Its start time is checked against the alert's. A mismatch means the
//     pid was reused, and nothing is signalled.
//  3. The signal goes through the pidfd. If the pinned process has exited
//     since step 1, the kernel returns ESRCH even if the pid was reused
//     again, so a newer process can never be hit.
func pidfdKill(pid uint32, startBootNS uint64) error {
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return fmt.Errorf("pidfd_open: %w", err)
	}
	defer unix.Close(fd)

	ticks, err := procStartTicks(pid)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return syscall.ESRCH
		}
		return err
	}
	if ticks != startBootNS/nsPerTick {
		return errPIDReused
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != nil {
		return fmt.Errorf("pidfd_send_signal: %w", err)
	}
	return nil
}

// procStartTicks returns field 22 (starttime) of /proc/<pid>/stat.
func procStartTicks(pid uint32) (uint64, error) {
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, err
	}
	return parseStartTicks(string(b))
}

// parseStartTicks extracts starttime from a /proc/<pid>/stat line. comm
// (field 2) may contain spaces and parentheses, so fields are counted from
// the last ')'.
func parseStartTicks(stat string) (uint64, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, fmt.Errorf("malformed stat: no comm terminator")
	}
	fields := strings.Fields(stat[end+1:]) // fields[0] is field 3 (state)
	const startTimeIdx = 22 - 3
	if len(fields) <= startTimeIdx {
		return 0, fmt.Errorf("malformed stat: %d fields after comm", len(fields))
	}
	return strconv.ParseUint(fields[startTimeIdx], 10, 64)
}
