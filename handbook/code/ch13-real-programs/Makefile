# Build in the lab VM (Alpine: gcc makes static PIEs with -static-pie).
showstack: showstack.c
	gcc -O2 -Wall -static-pie -o $@ $<
