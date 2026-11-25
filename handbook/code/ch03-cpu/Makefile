# Chapter 3: a tiny C program as machine code.
# make        build tiny (with debug info) and tiny.s (the assembly)
# make run    run it; the exit status is the answer (10)
# make dis    disassemble add, sum_to and main with objdump
# make gdb    step through two calls in gdb (see step.gdb)

CC = gcc

all: tiny tiny.s

tiny: tiny.c
	$(CC) -O1 -g -o $@ $<

# The two -fno-...-tables flags drop the .cfi lines. They are notes
# for debuggers and exception unwinding, not instructions for the CPU.
tiny.s: tiny.c
	$(CC) -O1 -S -fno-asynchronous-unwind-tables -fno-unwind-tables \
	    -o $@ $<

run: tiny
	./tiny; echo "exit status: $$?"

dis: tiny
	objdump -d tiny | awk '/<(add|sum_to|main)>:/,/^$$/'

gdb: tiny
	gdb -q -batch -x step.gdb ./tiny

clean:
	rm -f tiny tiny.s

.PHONY: all run dis gdb clean
