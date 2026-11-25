# Build: make        Run: ./box /bin/sh   (as a normal user, no sudo)
CC     = gcc
CFLAGS = -O2 -Wall

box: box.c filter.c
	$(CC) $(CFLAGS) -o $@ box.c filter.c

.PHONY: all
all: box
