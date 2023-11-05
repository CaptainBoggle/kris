# Set the KDIR variable to the path of your kernel source tree.
KDIR ?= /lib/modules/$(shell uname -r)/build

# Here, we first tell make to change to the kernel source directory,
# where the kernel build system is located. By setting M to the current
# directory, we tell the kernel build system to look for the Makefile
# in the current directory.
# From the makefile in the kernel source tree:
# "Use make M=dir to specify directory of external module to build"
all:
	$(MAKE) -C $(KDIR) M=$$PWD
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
