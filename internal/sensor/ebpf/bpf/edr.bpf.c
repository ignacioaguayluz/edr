// SPDX-License-Identifier: GPL-2.0
// EDR kernel sensor: emits process, file and network events to a ring buffer.
// CO-RE: compiled once against vmlinux.h, relocated at load time via BTF.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define COMM_LEN 16
#define MAX_PATH 256
#define MAX_ARGS 256
#define AF_INET  2
#define AF_INET6 10

enum event_kind {
	EV_EXEC    = 1,
	EV_EXIT    = 2,
	EV_OPEN    = 3,
	EV_CONNECT = 4,
};

struct event {
	__u64 ts_ns;      // CLOCK_MONOTONIC
	__u64 start_ns;   // process start, CLOCK_BOOTTIME (identity with pid)
	__u32 kind;
	__u32 pid;        // tgid in the initial pid namespace
	__u32 ppid;
	__u32 uid;
	__s32 exit_code;  // raw wait status (EV_EXIT)
	__u32 flags;      // open flags (EV_OPEN)
	__u32 args_len;   // valid bytes in args (EV_EXEC)
	__u16 family;     // EV_CONNECT
	__u16 dport;      // host byte order
	__u8 daddr[16];
	__u8 comm[COMM_LEN];
	__u8 path[MAX_PATH];  // exec filename or opened path, NUL-terminated
	__u8 args[MAX_ARGS];  // NUL-separated argv
};

// Set by the loader so the agent never observes (and feeds back on) itself.
const volatile __u32 agent_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Events lost because the ring buffer was full (user space too slow or a
// deliberate flood). Per-CPU, so increments need no atomics.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(&dropped, &key);
	if (v)
		(*v)++;
}

// Forces BTF emission of struct event for bpf2go -type event.
const struct event *unused_event __attribute__((unused));

static __always_inline struct event *new_event(__u32 kind)
{
	__u64 id = bpf_get_current_pid_tgid();
	__u32 tgid = id >> 32;
	if (tgid == agent_tgid)
		return NULL;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ts_ns = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	// The group leader's start time is what /proc/<pid>/stat reports, so
	// user space can verify it is acting on this exact process instance.
	e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->exit_code = 0;
	e->flags = 0;
	e->args_len = 0;
	e->family = 0;
	e->dport = 0;
	e->path[0] = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event *e = new_event(EV_EXEC);
	if (!e)
		return 0;

	unsigned int off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), (void *)ctx + off);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned long start = BPF_CORE_READ(task, mm, arg_start);
	unsigned long end = BPF_CORE_READ(task, mm, arg_end);
	unsigned long len = end - start;
	if (len >= MAX_ARGS)
		len = MAX_ARGS - 1;
	len &= MAX_ARGS - 1; // explicit bound for the verifier
	if (bpf_probe_read_user(&e->args, len, (void *)start) == 0)
		e->args_len = len;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(void *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)id != (__u32)(id >> 32))
		return 0; // a thread, not the whole process

	struct event *e = new_event(EV_EXIT);
	if (!e)
		return 0;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->exit_code = BPF_CORE_READ(task, exit_code);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e = new_event(EV_OPEN);
	if (!e)
		return 0;
	bpf_probe_read_user_str(&e->path, sizeof(e->path), (const char *)ctx->args[1]);
	e->flags = (__u32)ctx->args[2];
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr *sa = (struct sockaddr *)ctx->args[1];
	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), &sa->sa_family))
		return 0;
	if (family != AF_INET && family != AF_INET6)
		return 0; // ignore unix sockets etc.

	struct event *e = new_event(EV_CONNECT);
	if (!e)
		return 0;
	e->family = family;
	if (family == AF_INET) {
		struct sockaddr_in sin = {};
		bpf_probe_read_user(&sin, sizeof(sin), sa);
		e->dport = bpf_ntohs(sin.sin_port);
		__builtin_memcpy(&e->daddr, &sin.sin_addr.s_addr, 4);
	} else {
		struct sockaddr_in6 sin6 = {};
		bpf_probe_read_user(&sin6, sizeof(sin6), sa);
		e->dport = bpf_ntohs(sin6.sin6_port);
		__builtin_memcpy(&e->daddr, &sin6.sin6_addr, 16);
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
