/*
 * eBPF Programs for MCP Security Dynamic Analysis
 *
 * This file contains kernel-space eBPF probes for monitoring:
 * - File system operations (openat, read, write, unlinkat)
 * - Network activities (connect)
 * - Process management (execve, fork)
 *
 * Uses TRACEPOINT_PROBE for architecture independence (x86/ARM).
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>

// Event types for userspace communication
#define EVENT_FILE_OPEN     1
#define EVENT_FILE_READ     2
#define EVENT_FILE_WRITE    3
#define EVENT_FILE_UNLINK   4
#define EVENT_NET_SOCKET    5
#define EVENT_NET_CONNECT   6
#define EVENT_NET_SEND      7
#define EVENT_NET_RECV      8
#define EVENT_PROC_EXEC     9
#define EVENT_PROC_FORK     10
#define EVENT_ENV_ACCESS    11

// Maximum path/command length
#define MAX_PATH_LEN 256

// Event structure passed to userspace
struct event_data {
    u32 event_type;
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
    u64 timestamp;
    u64 size;           // File size or network bytes
    u32 flags;          // Open flags or socket type
    u32 fd;             // File descriptor
    u32 addr_family;    // AF_INET, AF_INET6, AF_UNIX
    u32 port;           // Network port
    u8  ip[16];         // IPv4/IPv6 address
};

// Temporary storage for open/openat arguments
struct open_args_t {
    char fname[MAX_PATH_LEN];
    u32 flags;
};

// Persistent storage for FD info
struct fd_info_t {
    char fname[MAX_PATH_LEN];
};

BPF_PERF_OUTPUT(events);

// Per-CPU arrays to avoid stack limit issues
BPF_PERCPU_ARRAY(event_heap, struct event_data, 1);
BPF_PERCPU_ARRAY(open_args_heap, struct open_args_t, 1);
BPF_PERCPU_ARRAY(fd_info_heap, struct fd_info_t, 1);

// ============================================================================
// STATE MANAGEMENT (FD -> Filename Mapping)
// ============================================================================

BPF_HASH(active_opens, u64, struct open_args_t);
BPF_HASH(fd_info, u64, struct fd_info_t);

// Helpers
static inline u32 get_curr_pid() {
    return bpf_get_current_pid_tgid() >> 32;
}

static inline u64 get_curr_tid() {
    return bpf_get_current_pid_tgid();
}

static inline bool is_ignored() {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    // Check for "ebpf-monitor"
    // We check enough characters to be reasonably sure
    if (comm[0] == 'e' && comm[1] == 'b' && comm[2] == 'p' && comm[3] == 'f' && 
        comm[4] == '-' && comm[5] == 'm') return true;
    return false;
}

// ============================================================================
// FILE SYSTEM MONITORING
// ============================================================================

// Tracepoint: openat (Enter)
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    if (is_ignored()) return 0;

    u64 tid = get_curr_tid();
    u32 zero = 0;
    struct open_args_t *args_data = open_args_heap.lookup(&zero);
    
    if (args_data) {
        __builtin_memset(args_data, 0, sizeof(*args_data));
        bpf_probe_read_user_str(args_data->fname, sizeof(args_data->fname), args->filename);
        args_data->flags = args->flags;
        active_opens.update(&tid, args_data);
    }
    return 0;
}

// Tracepoint: openat (Exit)
TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    if (is_ignored()) return 0;

    u64 tid = get_curr_tid();
    struct open_args_t *saved_args = active_opens.lookup(&tid);
    
    if (saved_args == NULL) return 0;
    
    int ret_fd = args->ret;
    
    if (ret_fd >= 0) {
        u64 key = ((u64)get_curr_pid() << 32) | (u32)ret_fd;
        u32 zero = 0;
        struct fd_info_t *info = fd_info_heap.lookup(&zero);
        if (info) {
            __builtin_memset(info, 0, sizeof(*info));
            __builtin_memcpy(info->fname, saved_args->fname, sizeof(info->fname));
            fd_info.update(&key, info);
        }
        
        struct event_data *event = event_heap.lookup(&zero);
        if (event) {
            __builtin_memset(event, 0, sizeof(*event));
            event->event_type = EVENT_FILE_OPEN;
            event->pid = get_curr_pid();
            event->uid = bpf_get_current_uid_gid();
            event->timestamp = bpf_ktime_get_ns();
            event->fd = ret_fd;
            event->flags = saved_args->flags;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->path, saved_args->fname, sizeof(event->path));
            
            events.perf_submit(args, event, sizeof(*event));
        }
    }
    
    active_opens.delete(&tid);
    return 0;
}

// Tracepoint: read (Enter)
TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    if (is_ignored()) return 0;

    u32 fd = args->fd;
    u64 key = ((u64)get_curr_pid() << 32) | fd;
    
    struct fd_info_t *info = fd_info.lookup(&key);
    
    if (info) {
        u32 zero = 0;
        struct event_data *event = event_heap.lookup(&zero);
        if (event) {
            __builtin_memset(event, 0, sizeof(*event));
            event->event_type = EVENT_FILE_READ;
            event->pid = get_curr_pid();
            event->uid = bpf_get_current_uid_gid();
            event->timestamp = bpf_ktime_get_ns();
            event->fd = fd;
            event->size = args->count;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->path, info->fname, sizeof(event->path));
            
            events.perf_submit(args, event, sizeof(*event));
        }
    }
    return 0;
}

// Tracepoint: write (Enter)
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    if (is_ignored()) return 0;

    u32 fd = args->fd;
    u64 key = ((u64)get_curr_pid() << 32) | fd;
    
    struct fd_info_t *info = fd_info.lookup(&key);
    
    if (info) {
        u32 zero = 0;
        struct event_data *event = event_heap.lookup(&zero);
        if (event) {
            __builtin_memset(event, 0, sizeof(*event));
            event->event_type = EVENT_FILE_WRITE;
            event->pid = get_curr_pid();
            event->uid = bpf_get_current_uid_gid();
            event->timestamp = bpf_ktime_get_ns();
            event->fd = fd;
            event->size = args->count;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            __builtin_memcpy(event->path, info->fname, sizeof(event->path));
            
            events.perf_submit(args, event, sizeof(*event));
        }
    }
    return 0;
}

// Tracepoint: close (Enter)
TRACEPOINT_PROBE(syscalls, sys_enter_close) {
    if (is_ignored()) return 0;

    u32 fd = args->fd;
    u64 key = ((u64)get_curr_pid() << 32) | fd;
    fd_info.delete(&key);
    return 0;
}

// Tracepoint: unlinkat (Enter)
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    if (is_ignored()) return 0;

    u32 zero = 0;
    struct event_data *event = event_heap.lookup(&zero);
    if (event) {
        __builtin_memset(event, 0, sizeof(*event));
        event->event_type = EVENT_FILE_UNLINK;
        event->pid = get_curr_pid();
        event->uid = bpf_get_current_uid_gid();
        event->timestamp = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_probe_read_user_str(event->path, sizeof(event->path), args->pathname);
        
        events.perf_submit(args, event, sizeof(*event));
    }
    return 0;
}

// ============================================================================
// PROCESS MONITORING
// ============================================================================

// Tracepoint: execve (Enter)
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    if (is_ignored()) return 0;

    u32 zero = 0;
    struct event_data *event = event_heap.lookup(&zero);
    if (event) {
        __builtin_memset(event, 0, sizeof(*event));
        event->event_type = EVENT_PROC_EXEC;
        event->pid = get_curr_pid();
        event->uid = bpf_get_current_uid_gid();
        event->timestamp = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        bpf_probe_read_user_str(event->path, sizeof(event->path), args->filename);
        
        events.perf_submit(args, event, sizeof(*event));
    }
    return 0;
}

// Tracepoint: fork (Sched)
TRACEPOINT_PROBE(sched, sched_process_fork) {
    if (is_ignored()) return 0;

    u32 zero = 0;
    struct event_data *event = event_heap.lookup(&zero);
    if (event) {
        __builtin_memset(event, 0, sizeof(*event));
        event->event_type = EVENT_PROC_FORK;
        event->pid = get_curr_pid();
        event->uid = bpf_get_current_uid_gid();
        event->timestamp = bpf_ktime_get_ns();
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        events.perf_submit(args, event, sizeof(*event));
    }
    return 0;
}

// ============================================================================
// NETWORK MONITORING
// ============================================================================

// Tracepoint: connect (Enter)
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    if (is_ignored()) return 0;

    u32 zero = 0;
    struct event_data *event = event_heap.lookup(&zero);
    if (event) {
        __builtin_memset(event, 0, sizeof(*event));
        event->event_type = EVENT_NET_CONNECT;
        event->pid = get_curr_pid();
        event->uid = bpf_get_current_uid_gid();
        event->timestamp = bpf_ktime_get_ns();
        event->fd = args->fd;
        
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        
        struct sockaddr *uaddr = (struct sockaddr *)args->uservaddr;
        
        // Read family first
        short family = 0;
        bpf_probe_read_user(&family, sizeof(family), &uaddr->sa_family);
        event->addr_family = family;
        
        if (family == AF_INET) {
            struct sockaddr_in sin = {};
            bpf_probe_read_user(&sin, sizeof(sin), uaddr);
            event->port = __builtin_bswap16(sin.sin_port);
            __builtin_memcpy(event->ip, &sin.sin_addr, 4);
        } 
        else if (family == AF_INET6) {
            struct sockaddr_in6 sin6 = {};
            bpf_probe_read_user(&sin6, sizeof(sin6), uaddr);
            event->port = __builtin_bswap16(sin6.sin6_port);
            __builtin_memcpy(event->ip, &sin6.sin6_addr, 16);
        } 
        else if (family == AF_UNIX) {
            struct sockaddr_un sun = {};
            bpf_probe_read_user(&sun, sizeof(sun), uaddr);
            bpf_probe_read_user_str(event->path, sizeof(event->path), sun.sun_path);
        }
        
        events.perf_submit(args, event, sizeof(*event));
    }
    return 0;
}