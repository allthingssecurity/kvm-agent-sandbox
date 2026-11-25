# step.gdb: watch the program counter (pc), the link register (x30)
# and the stack pointer (sp) across two calls. Run it with: make gdb
set pagination off
set print frame-info location-and-address
break sum_to
run
echo \n--- 1. sum_to just started: x30 points back into main\n
info registers pc x30 sp
x/i $x30
echo \n--- 2. three instructions later: stp saved x29 and x30\n
stepi 3
info registers pc sp
x/2gx $sp
echo \n--- 3. stop on the bl, then execute it\n
break *sum_to+36
continue
x/i $pc
stepi
info registers pc x30
echo \n--- 4. add's two instructions: add, then ret to x30\n
stepi 2
info registers pc
delete
continue
