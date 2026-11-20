// Package telemetry defines the kernel-independent endpoint event model.
// Sensors translate raw kernel data into these types; detection and
// response only ever see this model.
package telemetry

import (
	"strconv"
	"strings"
	"time"
)

// Kind identifies the type of endpoint activity an Event describes.
type Kind string

const (
	KindProcessExec Kind = "process_exec"
	KindProcessExit Kind = "process_exit"
	KindFileOpen    Kind = "file_open"
	KindNetConnect  Kind = "net_connect"
)

// Process describes the process that produced an event.
type Process struct {
	PID        uint32   `json:"pid"`
	PPID       uint32   `json:"ppid"`
	UID        uint32   `json:"uid"`
	Comm       string   `json:"comm"`
	Exe        string   `json:"exe,omitempty"`
	Args       []string `json:"args,omitempty"`
	ParentComm string   `json:"parent_comm,omitempty"`
	ExitCode   *int     `json:"exit_code,omitempty"`
}

// File describes a file access.
type File struct {
	Path  string `json:"path"`
	Flags uint32 `json:"flags"`
}

// Network describes an outbound connection attempt.
type Network struct {
	Family  string `json:"family"`
	DstIP   string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`
}

// Event is a single normalized piece of endpoint telemetry.
type Event struct {
	Time    time.Time `json:"time"`
	Kind    Kind      `json:"kind"`
	Process Process   `json:"process"`
	File    *File     `json:"file,omitempty"`
	Network *Network  `json:"network,omitempty"`
}

// Field returns the string value of a dotted field name, used by detection
// rules. The boolean is false when the field does not apply to this event.
func (e Event) Field(name string) (string, bool) {
	switch name {
	case "kind":
		return string(e.Kind), true
	case "process.pid":
		return strconv.FormatUint(uint64(e.Process.PID), 10), true
	case "process.ppid":
		return strconv.FormatUint(uint64(e.Process.PPID), 10), true
	case "process.uid":
		return strconv.FormatUint(uint64(e.Process.UID), 10), true
	case "process.comm":
		return e.Process.Comm, true
	case "process.exe":
		return e.Process.Exe, e.Process.Exe != ""
	case "process.args":
		return strings.Join(e.Process.Args, " "), len(e.Process.Args) > 0
	case "process.parent_comm":
		return e.Process.ParentComm, e.Process.ParentComm != ""
	case "file.path":
		if e.File == nil {
			return "", false
		}
		return e.File.Path, true
	case "network.family":
		if e.Network == nil {
			return "", false
		}
		return e.Network.Family, true
	case "network.dst_ip":
		if e.Network == nil {
			return "", false
		}
		return e.Network.DstIP, true
	case "network.dst_port":
		if e.Network == nil {
			return "", false
		}
		return strconv.FormatUint(uint64(e.Network.DstPort), 10), true
	}
	return "", false
}

// KnownFields lists every field name accepted by Field. Rule loading uses it
// to reject typos at startup instead of silently never matching.
var KnownFields = map[string]bool{
	"kind": true, "process.pid": true, "process.ppid": true, "process.uid": true,
	"process.comm": true, "process.exe": true, "process.args": true,
	"process.parent_comm": true, "file.path": true, "network.family": true,
	"network.dst_ip": true, "network.dst_port": true,
}
