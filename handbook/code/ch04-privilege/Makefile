# Chapter 4: privilege levels and system calls (arm64 only).
# make          build privileged, hello (no libc) and hello-libc
# make try      run the three forbidden things; each one is killed
# make trace    strace both hellos to compare their system calls

CC = gcc

all: privileged hello hello-libc

privileged: privileged.c
	$(CC) -O1 -o $@ $<

# No C library, no start-up code: _start in hello.S is the first
# instruction that runs.
hello: hello.S
	$(CC) -nostdlib -static -o $@ $<

hello-libc: hello-libc.c
	$(CC) -O1 -o $@ $<

try: privileged
	./privileged sysreg; echo "exit status: $$?"
	./privileged irqoff; echo "exit status: $$?"
	./privileged kmem;   echo "exit status: $$?"

trace: hello hello-libc
	strace ./hello
	strace ./hello-libc

clean:
	rm -f privileged hello hello-libc

.PHONY: all try trace clean
