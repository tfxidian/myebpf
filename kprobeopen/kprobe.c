
// +build ignore

#include "common.h"

#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(u64),
        .max_entries = 1,
};

SEC("kprobe/sys_execve")
int kprobe_execve() {
        u32 key     = 0;
        u64 initval = 1, *valp;
	int pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("Hello, world, from BPF! My PID is %d\n", pid);
        valp = bpf_map_lookup_elem(&kprobe_map, &key);
        if (!valp) {
                bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
                return 0;
        }
        __sync_fetch_and_add(valp, 1);

        return 0;
}

