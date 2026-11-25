# Chapter 10: a yardstick for the cost of a VM exit. Run inside the lab.
CFLAGS = -O2 -Wall -Wextra

run: syscall-cost
	./syscall-cost

syscall-cost: syscall-cost.c
	$(CC) $(CFLAGS) -o $@ syscall-cost.c

.PHONY: run
