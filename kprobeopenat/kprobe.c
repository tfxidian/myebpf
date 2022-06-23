
// +build ignore

#include "common.h"
#include <bpf_helpers.h>
#include <linux/ptrace.h>
#include <bpf/bpf_core_read.h>
#include <bpf_tracing.h>

/*
#define bpf_printk(fmt, ...)                            \
({                                                      \
        char ____fmt[] = fmt;                           \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})
*/

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") kprobe_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(u64),
        .max_entries = 1,
};


SEC("kprobe/sys_openat")
int kprobe_openat(int dirfd, const char *pathname, int flags) {
        u32 key     = 0;
        u64 initval = 1, *valp;
	//int pid = bpf_get_current_pid_tgid() >> 32;
	char fmt[] = "@file_name='%s'";
	/*struct pt_regs *real_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
	int dirfd (struct pt_regs *)PT_REGS_PARM1= PT_REGS_PARM1_CORE(real_regs);
	char *pathname = (char *)PT_REGS_PARM2_CORE(real_regs);
	*/
	//unsigned long fd_id = ctx->rbx;
	//char* file_name = (char*)fd_id;
	bpf_trace_printk(fmt, sizeof(fmt), pathname);

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

