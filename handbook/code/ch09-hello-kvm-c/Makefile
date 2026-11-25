# Chapter 9: hello, KVM in C. Needs an arm64 Linux host with /dev/kvm,
# gcc, make and the Linux UAPI headers (Alpine: linux-headers,
# Debian/Ubuntu: linux-libc-dev).
#   make        build the VMM (hello-kvm) and the guest image (guest.bin)
#   make run    run the VM
#   make dump   disassemble the guest
CFLAGS = -O2 -Wall -Wextra

all: hello-kvm guest.bin

hello-kvm: hello-kvm.c
	$(CC) $(CFLAGS) -o $@ hello-kvm.c

# The guest is assembled for the same CPU, then stripped down to raw bytes:
# no ELF header, just the instructions and the string, ready to copy into RAM.
guest.o: guest.S
	$(CC) -c -o $@ guest.S

guest.bin: guest.o
	objcopy -O binary guest.o $@

run: all
	./hello-kvm guest.bin

dump: guest.o
	objdump -d guest.o

clean:
	rm -f hello-kvm guest.o guest.bin

.PHONY: all run dump clean
