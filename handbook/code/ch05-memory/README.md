# Chapter 5 code: memory and exploits

Build and run in the lab (any Linux, arm64 or x86-64):

    make
    ./maps                 # where things live, then /proc/self/maps
    ./overflow Alice       # normal run
    ./attack.sh            # overflow name[] into greet, call secret()
    ./attack.sh ./overflow-pie   # same attack with ASLR: it misses
    ./nx                   # run code from the stack: SIGSEGV (W^X)
    ./nx mprotect          # same code in an r-x page: returns 42
    ./canary AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   # canary fires
