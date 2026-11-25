# Chapter 2: check your lab

`check-lab.sh` checks that this machine can run the book's examples. It prints one
line per check (`OK`, `MISSING`, or `NOTE` for optional things) and exits with
status 0 only if nothing is missing. No root needed.

Run it on the Linux machine (in the lab: inside the Lima VM):

    sh check-lab.sh

To see what the kernel-header check says when the headers don't match, pretend
the running kernel is another version:

    KERNEL_RELEASE=6.18.22-0-virt sh check-lab.sh
