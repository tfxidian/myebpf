
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched/clock.h>
#include <linux/kprobes.h>
#include <linux/errno.h>
#include <linux/stddef.h>
#include <linux/bug.h>
#include <linux/ptrace.h>

#include <linux/socket.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/net.h>

#include <linux/inet.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/inet_common.h>


/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
    .symbol_name    = "inet_bind",
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{

#ifdef CONFIG_ARM64
    struct socket *sock = regs->regs[0];
    struct sockaddr *uaddr = regs->regs[1];
#endif

#ifdef CONFIG_X86
    struct socket *sock = regs->di;
    struct sockaddr *uaddr = regs->si;
#endif

    struct sockaddr_in *addr =  (struct sockaddr_in *)uaddr;
    unsigned short snum = ntohs(addr->sin_port);

    pr_info("%s name:%s pid:%d socket bind port=%d\n",
            p->symbol_name, current->comm, task_pid_nr(current), snum);

    return 0;
}
/* kprobe post_handler: called after the probed instruction is executed */
static void handler_post(struct kprobe *p, struct pt_regs *regs,
        unsigned long flags)
{
    pr_info("%s called\n", __func__);
}

/*
 * fault_handler: this is called if an exception is generated for any
 * instruction within the pre- or post-handler, or when Kprobes
 * single-steps the probed instruction.
 */
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
    printk(KERN_INFO "fault_handler: p->addr = 0x%p, trap #%dn",
            p->addr, trapnr);
    /* Return 0 because we don't handle the fault. */
    return 0;
}

static int __init kprobe_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Planted kprobe at %p\n", kp.addr);
    return 0;
}

static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
