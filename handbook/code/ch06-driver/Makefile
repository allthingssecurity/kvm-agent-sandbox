# Build: make         Load: sudo insmod hello.ko     Unload: sudo rmmod hello
# kbuild builds the module; the user program is a normal gcc build.
obj-m := hello.o

KDIR ?= /lib/modules/$(shell uname -r)/build

all: hello.ko hello_user

hello.ko: hello.c hello_ioctl.h
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

hello_user: hello_user.c hello_ioctl.h
	gcc -O2 -Wall -o $@ hello_user.c

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
