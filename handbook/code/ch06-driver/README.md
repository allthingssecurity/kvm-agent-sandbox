# Chapter 6 code: /dev/hello, a first device driver

Build and run in the lab (needs kernel headers for the running kernel):

    make                      # builds hello.ko (kbuild) and hello_user
    sudo insmod hello.ko
    dmesg | tail -2
    ls -l /dev/hello
    ./hello_user
    sudo rmmod hello          # always unload when you are done
