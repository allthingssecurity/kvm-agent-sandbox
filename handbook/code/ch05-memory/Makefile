# Build: make        Run: see README.md
CC      = gcc
CFLAGS  = -O0 -g -Wall -U_FORTIFY_SOURCE

all: maps overflow overflow-pie nx canary canary-off

maps: maps.c
	$(CC) $(CFLAGS) -o $@ $<

# No PIE: secret() has the same address on every run (see section 5.6).
overflow: overflow.c
	$(CC) $(CFLAGS) -no-pie -o $@ $<

# The same program as a normal PIE, loaded at a random address.
overflow-pie: overflow.c
	$(CC) $(CFLAGS) -fpie -pie -o $@ $<

nx: nx.c
	$(CC) $(CFLAGS) -o $@ $<

canary: canary.c
	$(CC) $(CFLAGS) -fstack-protector-strong -o $@ $<

canary-off: canary.c
	$(CC) $(CFLAGS) -fno-stack-protector -o $@ $<

.PHONY: all
