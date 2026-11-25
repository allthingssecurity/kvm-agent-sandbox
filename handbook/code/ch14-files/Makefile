# Build in the lab VM (Alpine: gcc makes static PIEs with -static-pie).
peek-tmp: peek-tmp.c
	gcc -O2 -Wall -static-pie -o $@ $<
