---
layout: post
title:  "NASM Assembler - Integer Overflow"
date:   2018-09-19 03:39:03 +0700
tags:
    - integer
---

Little Details
--------------
There's a integer overflow found in NASM assembler. This was found few years back (around 2012-2013). Don't have much info as I losing some of the analysis file. 

Crash triage:
```
id:000003,sig:11,src:000000,op:havoc,rep:32:3: warning: Unknown section attribute 'be' ignored on declaration of section `.datamus}'

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0xb7fc0000 --> 0x1a9da8 
ECX: 0x0 
EDX: 0x0 
ESI: 0x0 
EDI: 0x0 
EBP: 0xb7f61fa0 --> 0x20002 
ESP: 0xbfffeaf0 --> 0xbfffebfc --> 0x0 
EIP: 0xb7e4a842 (<__GI_____strtol_l_internal+82>:	movzx  eax,BYTE PTR [eax])
EFLAGS: 0x10283 (CARRY parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xb7e4a837 <__GI_____strtol_l_internal+71>:	mov    ebp,DWORD PTR [eax+0x34]
   0xb7e4a83a <__GI_____strtol_l_internal+74>:	mov    eax,DWORD PTR [esp+0x50]
   0xb7e4a83e <__GI_____strtol_l_internal+78>:	mov    DWORD PTR [esp+0x20],esi
=> 0xb7e4a842 <__GI_____strtol_l_internal+82>:	movzx  eax,BYTE PTR [eax]
   0xb7e4a845 <__GI_____strtol_l_internal+85>:	movsx  edx,al
   0xb7e4a848 <__GI_____strtol_l_internal+88>:	test   BYTE PTR [ebp+edx*2+0x1],0x20
   0xb7e4a84d <__GI_____strtol_l_internal+93>:	je     0xb7e4a86c <__GI_____strtol_l_internal+124>
   0xb7e4a84f <__GI_____strtol_l_internal+95>:	mov    edx,DWORD PTR [esp+0x20]
[------------------------------------stack-------------------------------------]
0000| 0xbfffeaf0 --> 0xbfffebfc --> 0x0 
0004| 0xbfffeaf4 --> 0xb7ff2500 (<_dl_runtime_resolve+16>:	pop    edx)
0008| 0xbfffeaf8 --> 0x81586b0 --> 0x0 
0012| 0xbfffeafc --> 0x61 ('a')
0016| 0xbfffeb00 --> 0x0 
0020| 0xbfffeb04 --> 0xbfffeb9c --> 0x8155b2c --> 0x706265 ('ebp')
0024| 0xbfffeb08 --> 0xb7e3ddf5 (<__ctype_b_loc+5>:	add    ecx,0x18220b)
0028| 0xbfffeb0c --> 0x804e47c (mov    edx,DWORD PTR [esp+0xc])
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0xb7e4a842 in __GI_____strtol_l_internal (nptr=nptr@entry=0x0, endptr=endptr@entry=0x0, base=base@entry=0xa, group=group@entry=0x0, loc=0xb7fc08a0 <_nl_global_locale>) at strtol_l.c:298
298	strtol_l.c: No such file or directory.

gdb-peda$ bt
#0  0xb7e4a842 in __GI_____strtol_l_internal (nptr=nptr@entry=0x0, endptr=endptr@entry=0x0, base=base@entry=0xa, group=group@entry=0x0, loc=0xb7fc08a0 <_nl_global_locale>) at strtol_l.c:298
#1  0xb7e4a607 in __GI_strtol (nptr=0x0, endptr=0x0, base=0xa) at strtol.c:108
#2  0x0805f1a4 in ?? ()
#3  0x080619b7 in ?? ()
#4  0x0804c375 in ?? ()
#5  0x0804a83c in ?? ()
#6  0xb7e2fa83 in __libc_start_main (main=0x8049cd0, argc=0x4, argv=0xbffff084, init=0x80843f0, fini=0x8084460, rtld_fini=0xb7fed180 <_dl_fini>, stack_end=0xbffff07c) at libc-start.c:287
#7  0x0804abae in ?? ()
```

Trace Call 
----------
```
                |-- arg[0]: 0xb7fc0960 --> 0xfbad2086 
                |-- arg[1]: 0x1 
                |-- arg[2]: 0x8084488 ("%s%s\n")
                |-- arg[3]: 0x808477b ("warning: ")
                |-- arg[4]: 0xbfffe6fc --> 0x1 
warning: Unknown section attribute 'be' ignored on declaration of section `.datamus}'
        dep:07 => 0x805f122:	call   0x804e620
               |-- arg[0]: 0x8155b26 
               |-- arg[1]: 0xbfffeb98 --> 0xb7e3ddf5 (<__ctype_b_loc+5>:	add    ecx,0x18220b)
               |-- arg[2]: 0xbfffeb9c --> 0x804e4cc (mov    edx,DWORD PTR [esp+0xc])
      dep:05 => 0x804e64a:	call   0x804e5d0
             |-- arg[0]: 0x8155b26 
             |-- arg[1]: 0xbfffeb4c --> 0x804e47c (mov    edx,DWORD PTR [esp+0xc])
       dep:06 => 0x804e5db:	call   0x804e460
              |-- arg[0]: 0x8155b26 
       dep:06 => 0x804e477:	call   0x8048f40 <__ctype_b_loc@plt>
       dep:06 => 0x804e5e5:	call   0x804e4b0
              |-- arg[0]: 0x8155b26 
       dep:06 => 0x804e4c7:	call   0x8048f40 <__ctype_b_loc@plt>
      dep:05 => 0x804e664:	call   0x8048d80 <strchr@plt>
             |-- arg[0]: 0x8155b26 
             |-- arg[1]: 0x3d ('=')
      dep:05 => 0x804e6c3:	call   0x804e460
             |-- arg[0]: 0x8155b2c 
       dep:06 => 0x804e477:	call   0x8048f40 <__ctype_b_loc@plt>
        dep:07 => 0x805f138:	call   0x8048db0 <strcasecmp@plt>
               |-- arg[0]: 0x8155b26 
               |-- arg[1]: 0x80e0064 ("align")
        dep:07 => 0x805f19f:	call   0x8048f00 <strtol@plt>
               |-- arg[0]: 0x0 
               |-- arg[1]: 0x0 
               |-- arg[2]: 0xa ('\n')
```
