// +build ignore

#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") counting_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

// This struct is defined according to the following format file:
// /sys/kernel/debug/tracing/events/kmem/mm_page_alloc/format
struct syscalls_enter_openat_args {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;
	long syscall_nr;
	long dfd;
	long filename_ptr;
	long flags;
	long mode;
};


// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(struct syscalls_enter_openat_args *ctx) {
	u32 key     = 0;
	u64 initval = 1, *valp;
		char msg[] = "Hello eBPF!";
	bpf_trace_printk(msg, sizeof(msg));
 	char fmt[] = "@dirfd='%d' @pathname='%s'";

	bpf_trace_printk(fmt, sizeof(fmt), ctx->dfd, (char *)ctx->filename_ptr);

	valp = bpf_map_lookup_elem(&counting_map, &key);
	if (!valp) {
		bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);
	return 0;
}
