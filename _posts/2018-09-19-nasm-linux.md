---
layout: post
title:  "CVE-2018-16382 - Netwide Assembler (NASM) – Buffer Overflow"
date:   2018-09-19 03:04:23 +0700
tags:
    - CVE-2018-16382
---

Description
-----------
Netwide Assembler (NASM) 2.14rc15 has a buffer over-read in x86/regflags.c.

Proof-of-Concept
----------------
An buffer overflow trigger upon fuzzing. We compiled the program with ASAN to see the result crash. Target version nasm-2.14rc15. 
The issue found by AFL. ASAN output:
```
==17458==ERROR: AddressSanitizer: global-buffer-overflow on address 0x0000008d8090 at pc 0x00000056d272 bp 0x7ffe65d7d2d0 sp 0x7ffe65d7d2c8
READ of size 8 at 0x0000008d8090 thread T0
    #0 0x56d271  (/home/john/fuzzing/nasm-2.14rc15/nasm+0x56d271)
    #1 0x50e027  (/home/john/fuzzing/nasm-2.14rc15/nasm+0x50e027)
    #2 0x7f8a4f7deb96  (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #3 0x41cac9  (/home/john/fuzzing/nasm-2.14rc15/nasm+0x41cac9)

0x0000008d8090 is located 8 bytes to the right of global variable 'nasm_reg_flags' defined in 'x86/regflags.c:6:17' (0x8d7900) of size 1928
SUMMARY: AddressSanitizer: global-buffer-overflow (/home/john/fuzzing/nasm-2.14rc15/nasm+0x56d271) 
Shadow bytes around the buggy address:
  0x000080112fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080112fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080112fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080112ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080113000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x000080113010: 00 f9[f9]f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x000080113020: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x000080113030: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x000080113040: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
  0x000080113050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x000080113060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==17458==ABORTING
```
