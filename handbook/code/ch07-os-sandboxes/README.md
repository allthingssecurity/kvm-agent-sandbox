# Chapter 7 code: a tiny container by hand

Build and run in the lab as a normal user (unprivileged user namespaces
must be allowed, which they are on Alpine):

    make
    ./box /bin/sh -c 'hostname; echo pid $$; ps; ip link'
    ./box nc -l -p 8080        # socket() is refused by the seccomp filter
