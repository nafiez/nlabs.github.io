---
layout: post
title:  "Microsoft Windows win32k.sys - Invalid Pointer Vulnerability (MSRC Case 48212)"
date:   2018-11-09 10:05:03 +0800
tags:
    - pointer
---

Overview
--------
There’s a kernel unhandled exception happened in GDI function **NtUserGetDCEx** and turn the OS to BSOD during boot-time. To trigger the issue it is required to have Administrator privilege to create **AppInit_DLL** registry key and a simple DLL that can pop a message box. In this case, we installed Anti-Virus called BullGuard (https://www.bullguard.com) in Windows 7 64-bit system with the registry AppInit_DLL and its DLL created. After installation, upon winlogon.exe taking place, a BSOD happened. We suspect the DLL mapped itself to winlogon.exe and this making the Windows itself prone to failed to dereference pointer in kernel thus making it BSOD. We believe this happened when BullGuard AV itself is vulnerable to AppInit_DLL technique and allowed to load the DLL during process start at winlogon.exe. It seems win32k.sys driver lacked of pointer checking during boot-time process. 

The issue has been reported to Microsoft (MSRC Case 48212) and the confirmed the finding are valid. Howevever the issue does not meet their service bar (which is required Administrator privilege to perform changes on the registry). 

It turns out that not only me to found the issue, **omeg** posted in OpenRCE forum regarding his finding too (http://www.openrce.org/blog/view/966/Null_pointer_dereference_in_win32k).

Crash Analysis
---------------------
Initial analysis found the root cause was coming from win32k!NtUserGetDCEx+b7.
```
BugCheck 3B, {c0000005, fffff9600016126f, fffff880045ceae0, 0}

*** WARNING: Unable to verify checksum for pwned.dll
*** ERROR: Module load completed but symbols could not be loaded for pwned.dll
Probably caused by : win32k.sys ( win32k!NtUserGetDCEx+b7 )

...

SYSTEM_SERVICE_EXCEPTION (3b)
An exception happened while executing a system service routine.
Arguments:
Arg1: 00000000c0000005, Exception code that caused the bugcheck
Arg2: fffff9600016126f, Address of the instruction which caused the bugcheck
Arg3: fffff880045ceae0, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

…

kd> r
Last set context:
rax=fffff900c011b010 rbx=fffffa8005095ac0 rcx=0000000000000000
rdx=0000000000000001 rsi=0000000000000000 rdi=0000000000000000
rip=fffff9600016126f rsp=fffff880045cf4b0 rbp=0000000000000000
 r8=0000000000000003  r9=0000000000000000 r10=fffff960001611b8
r11=000007fffffde000 r12=0000000000000000 r13=0000000000000003
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
win32k!NtUserGetDCEx+0xb7:
fffff960`0016126f 488b4108        mov     rax,qword ptr [rcx+8] ds:002b:00000000`00000008=????????????????
```
Looking at the BugCheck, it cause an SYSTEM_SERVICE_EXCEPTION (3b) and the first argument showing an Access Violation is happened during boot time. 
Stack trace:
```
STACK_TEXT:  
fffff880`045cf4b0 fffff800`02af39d3 : fffffa80`05095ac0 fffff880`045cf590 00000000`00000000 00000000`0024d810 : win32k!NtUserGetDCEx+0xb7
fffff880`045cf510 00000000`76dd564a : 00000000`76e321db 00000000`0024d810 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x13
00000000`0024d4f8 00000000`76e321db : 00000000`0024d810 00000000`00000000 00000000`00000000 00000000`00440000 : USER32!NtUserGetDCEx+0xa
00000000`0024d500 00000000`76e31c69 : 00000000`00447410 00000000`0044740b 00000000`00000008 00000000`77008795 : USER32!SoftModalMessageBox+0x21b
00000000`0024d630 00000000`76e314b7 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`0045b1e0 : USER32!MessageBoxWorker+0x31d
00000000`0024d7f0 00000000`76e3166a : 00000000`0045b1e0 000007fe`fcaa4000 00000000`0045d500 00000000`0045b1e0 : USER32!MessageBoxTimeoutW+0xb3
00000000`0024d8c0 00000000`76e31352 : 00000000`00000001 000007fe`0000000e 00000000`0024df00 00000000`00000000 : USER32!MessageBoxTimeoutA+0x18a
00000000`0024d930 000007fe`fca9101d : 00000000`00000001 000007fe`fca91721 00000000`00000000 00000000`0024df00 : USER32!MessageBoxA+0x4e
00000000`0024d970 00000000`00000001 : 000007fe`fca91721 00000000`00000000 00000000`0024df00 00000000`00000002 : pwned+0x101d
00000000`0024d978 000007fe`fca91721 : 00000000`00000000 00000000`0024df00 00000000`00000002 000007fe`fca91058 : 0x1
00000000`0024d980 00000000`00000000 : 00000000`0024df00 00000000`00000002 000007fe`fca91058 00000000`00000000 : pwned+0x1721
```
Full dump (!analyze -v)
```
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

SYSTEM_SERVICE_EXCEPTION (3b)
An exception happened while executing a system service routine.
Arguments:
Arg1: 00000000c0000005, Exception code that caused the bugcheck
Arg2: fffff9600016126f, Address of the instruction which caused the bugcheck
Arg3: fffff880045ceae0, Address of the context record for the exception that caused the bugcheck
Arg4: 0000000000000000, zero.

Debugging Details:
------------------


KEY_VALUES_STRING: 1


TIMELINE_ANALYSIS: 1


DUMP_CLASS: 1

DUMP_QUALIFIER: 0

BUILD_VERSION_STRING:  7601.24231.amd64fre.win7sp1_ldr.180810-0600

DUMP_TYPE:  0

BUGCHECK_P1: c0000005

BUGCHECK_P2: fffff9600016126f

BUGCHECK_P3: fffff880045ceae0

BUGCHECK_P4: 0

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.

FAULTING_IP: 
win32k!NtUserGetDCEx+b7
fffff960`0016126f 488b4108        mov     rax,qword ptr [rcx+8]

CONTEXT:  fffff880045ceae0 -- (.cxr 0xfffff880045ceae0)
rax=fffff900c011b010 rbx=fffffa8005095ac0 rcx=0000000000000000
rdx=0000000000000001 rsi=0000000000000000 rdi=0000000000000000
rip=fffff9600016126f rsp=fffff880045cf4b0 rbp=0000000000000000
 r8=0000000000000003  r9=0000000000000000 r10=fffff960001611b8
r11=000007fffffde000 r12=0000000000000000 r13=0000000000000003
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
win32k!NtUserGetDCEx+0xb7:
fffff960`0016126f 488b4108        mov     rax,qword ptr [rcx+8] ds:002b:00000000`00000008=????????????????
Resetting default scope

CPU_COUNT: 1

CPU_MHZ: 8f6

CPU_VENDOR:  GenuineIntel

CPU_FAMILY: 6

CPU_MODEL: 3d

CPU_STEPPING: 4

CPU_MICROCODE: 6,3d,4,0 (F,M,S,R)  SIG: 2A'00000000 (cache) 2A'00000000 (init)

DEFAULT_BUCKET_ID:  WIN7_DRIVER_FAULT

BUGCHECK_STR:  0x3B

PROCESS_NAME:  winlogon.exe

CURRENT_IRQL:  2

ANALYSIS_SESSION_HOST:  HEAVEN-PC

ANALYSIS_SESSION_TIME:  10-24-2018 21:44:25.0111

ANALYSIS_VERSION: 10.0.17134.1 amd64fre

LAST_CONTROL_TRANSFER:  from fffff80002af39d3 to fffff9600016126f

STACK_TEXT:  
fffff880`045cf4b0 fffff800`02af39d3 : fffffa80`05095ac0 fffff880`045cf590 00000000`00000000 00000000`0024d810 : win32k!NtUserGetDCEx+0xb7
fffff880`045cf510 00000000`76dd564a : 00000000`76e321db 00000000`0024d810 00000000`00000000 00000000`00000000 : nt!KiSystemServiceCopyEnd+0x13
00000000`0024d4f8 00000000`76e321db : 00000000`0024d810 00000000`00000000 00000000`00000000 00000000`00440000 : USER32!NtUserGetDCEx+0xa
00000000`0024d500 00000000`76e31c69 : 00000000`00447410 00000000`0044740b 00000000`00000008 00000000`77008795 : USER32!SoftModalMessageBox+0x21b
00000000`0024d630 00000000`76e314b7 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`0045b1e0 : USER32!MessageBoxWorker+0x31d
00000000`0024d7f0 00000000`76e3166a : 00000000`0045b1e0 000007fe`fcaa4000 00000000`0045d500 00000000`0045b1e0 : USER32!MessageBoxTimeoutW+0xb3
00000000`0024d8c0 00000000`76e31352 : 00000000`00000001 000007fe`0000000e 00000000`0024df00 00000000`00000000 : USER32!MessageBoxTimeoutA+0x18a
00000000`0024d930 000007fe`fca9101d : 00000000`00000001 000007fe`fca91721 00000000`00000000 00000000`0024df00 : USER32!MessageBoxA+0x4e
00000000`0024d970 00000000`00000001 : 000007fe`fca91721 00000000`00000000 00000000`0024df00 00000000`00000002 : pwned+0x101d
00000000`0024d978 000007fe`fca91721 : 00000000`00000000 00000000`0024df00 00000000`00000002 000007fe`fca91058 : 0x1
00000000`0024d980 00000000`00000000 : 00000000`0024df00 00000000`00000002 000007fe`fca91058 00000000`00000000 : pwned+0x1721


THREAD_SHA1_HASH_MOD_FUNC:  28860cd61556fec47ee8b98cee370782542f9f75

THREAD_SHA1_HASH_MOD_FUNC_OFFSET:  96b696341545d28bd11ab89cef209459add5d6ad

THREAD_SHA1_HASH_MOD:  733a7efb513a8a4310aebdea1f93670be82694d5

FOLLOWUP_IP: 
win32k!NtUserGetDCEx+b7
fffff960`0016126f 488b4108        mov     rax,qword ptr [rcx+8]

FAULT_INSTR_CODE:  8418b48

SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  win32k!NtUserGetDCEx+b7

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: win32k

IMAGE_NAME:  win32k.sys

DEBUG_FLR_IMAGE_TIMESTAMP:  5b40db20

IMAGE_VERSION:  6.1.7601.24204

STACK_COMMAND:  .cxr 0xfffff880045ceae0 ; kb

FAILURE_BUCKET_ID:  X64_0x3B_win32k!NtUserGetDCEx+b7

BUCKET_ID:  X64_0x3B_win32k!NtUserGetDCEx+b7

PRIMARY_PROBLEM_CLASS:  X64_0x3B_win32k!NtUserGetDCEx+b7

TARGET_TIME:  2018-10-24T13:30:00.000Z

OSBUILD:  7601

OSSERVICEPACK:  1000

SERVICEPACK_NUMBER: 0

OS_REVISION: 0

SUITE_MASK:  272

PRODUCT_TYPE:  1

OSPLATFORM_TYPE:  x64

OSNAME:  Windows 7

OSEDITION:  Windows 7 WinNt (Service Pack 1) TerminalServer SingleUserTS

OS_LOCALE:  

USER_LCID:  0

OSBUILD_TIMESTAMP:  2018-08-10 23:14:00

BUILDDATESTAMP_STR:  180810-0600

BUILDLAB_STR:  win7sp1_ldr

BUILDOSVER_STR:  6.1.7601.24231.amd64fre.win7sp1_ldr.180810-0600

ANALYSIS_SESSION_ELAPSED_TIME:  a8b

ANALYSIS_SOURCE:  KM

FAILURE_ID_HASH_STRING:  km:x64_0x3b_win32k!ntusergetdcex+b7

FAILURE_ID_HASH:  {c08a00a3-15a5-89cf-350a-72fc675556fc}

Followup:     MachineOwner
---------
```

Vulnerability Analysis
----------------------
Looking at the registers output, we can see an invalid pointer is happening:
```
kd> r
Last set context:
rax=fffff900c011b010 rbx=fffffa8005095ac0 rcx=0000000000000000
rdx=0000000000000001 rsi=0000000000000000 rdi=0000000000000000
rip=fffff9600016126f rsp=fffff880045cf4b0 rbp=0000000000000000
 r8=0000000000000003  r9=0000000000000000 r10=fffff960001611b8
r11=000007fffffde000 r12=0000000000000000 r13=0000000000000003
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl zr na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010246
win32k!NtUserGetDCEx+0xb7:
fffff960`0016126f 488b4108        mov     rax,qword ptr [rcx+8] ds:002b:00000000`00000008=????????????????
```
Inspecting the pointer **rcx+8** to view the memory address it referencing and we can confirm the memory are indeed invalid / free. There could be a potential of attacker to control from here when mapping into winlogon.exe process by overwriting something in the memory to control the object.
```
kd> dd rcx+8
00000000`00000008  ???????? ???????? ???????? ????????
00000000`00000018  ???????? ???????? ???????? ????????
00000000`00000028  ???????? ???????? ???????? ????????
00000000`00000038  ???????? ???????? ???????? ????????
00000000`00000048  ???????? ???????? ???????? ????????
00000000`00000058  ???????? ???????? ???????? ????????
00000000`00000068  ???????? ???????? ???????? ????????
00000000`00000078  ???????? ???????? ???????? ????????
```
Disassembly code of the crash path:
```
kd> u win32k!NtUserGetDCEx+0xb7
win32k!NtUserGetDCEx+0xb7:
fffff960`0016126f 488b4108        mov     rax,qword ptr [rcx+8]      // ds:002b:00000000`00000008=????????????????
fffff960`00161273 488b7810        mov     rdi,qword ptr [rax+10h]
fffff960`00161277 ff15936d1d00    call    qword ptr [win32k!_imp_PsGetCurrentThreadWin32Thread (fffff960`00338010)]
fffff960`0016127d 0fbaa0980100001d bt      dword ptr [rax+198h],1Dh
fffff960`00161285 731c            jae     win32k!NtUserGetDCEx+0xeb (fffff960`001612a3)
fffff960`00161287 ff15836d1d00    call    qword ptr [win32k!_imp_PsGetCurrentThreadWin32Thread (fffff960`00338010)]
fffff960`0016128d 488b8858010000  mov     rcx,qword ptr [rax+158h]
fffff960`00161294 488b81b0020000  mov     rax,qword ptr [rcx+2B0h]
```
