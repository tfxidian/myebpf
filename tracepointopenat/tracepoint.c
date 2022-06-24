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

struct syscalls_enter_connect_args {
  __u64 __dont_touch;
  __u64 syscall_nr;
  __u64 fd;
  __u64 sockaddr;
  __u64 addrlen;
};

struct sockaddr {
   unsigned short   sa_family;
   char             sa_data[14];
};

// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/syscalls/sys_enter_connect")
int sys_enter_connect(struct syscalls_enter_connect_args *ctx) {
	u32 key     = 0;
	u64 initval = 1, *valp;
		char msg[] = "Hello eBPF!";
	bpf_trace_printk(msg, sizeof(msg));
 	char fmt[] = "@dirfd='%d' @sockaddr='%s'";
	bpf_printk("syscall_nr: %d", ctx->syscall_nr);
	bpf_trace_printk(fmt, sizeof(fmt), ctx->addrlen, ((struct sockaddr *)ctx->sockaddr)->sa_data);

	valp = bpf_map_lookup_elem(&counting_map, &key);
	if (!valp) {
		bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);
	return 0;
}
