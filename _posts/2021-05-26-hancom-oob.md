---
layout: post
title:  "(0-Day?) Hancom Word Out-of-Bounds Read Vulnerability"
date:   2021-05-26 18:00:00 +0800
tags:
    - OOB
---

Overview
-----------
Hancom Office 2020 provides a feature-rich set of desktop productivity applications for conducting common tasks such as word processing, spreadsheet modelling, graphic presentation and working with PDFs. With an intuitive interface and powerful features, Hancom Office can bring out the true professional in you today.

Vulnerability Description
-------------------------
An heap out-of-bounds read vulnerability exists in Hancom Word software that is caused when the Office software improperly handles objects in memory while parsing specially crafted Office files. An attacker who successfully exploited the vulnerability remotely and could run arbitrary code in the context of the current user. Failure could lead to denial-of-service. Product and version affected was Hancom Office 2020 with version 11.0.0.1. The vulnerability was found with fuzzing. A heap overflow occurred when parsing a specially crafted document file that could allow to execute arbitrary code, remotely. Access violation happened when attaching with debugger.
```
(39c.d14): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=5c002000 ebx=0d046af0 ecx=5c002000 edx=577d8b18 esi=0cf34250 edi=00000000
eip=6aa18f9a esp=00f7e20c ebp=00f7e20c iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00210206
HwordApp!HwordDeletePropertyArray+0xa5ee1a:
6aa18f9a 8b480c          mov     ecx,dword ptr [eax+0Ch] ds:002b:5c00200c=????????

0:000> .exr -1 
ExceptionAddress: 6aa18f9a (HwordApp!HwordDeletePropertyArray+0x00a5ee1a)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 00000000
   Parameter[1]: 5c00200c
Attempt to read from address 5c00200c
```

Disclosure timeline
-------------------
The vulnerability was reported back August 2020. Timeline of disclosure:
- 2020-08-16 - Informing vendor (Hancom) on vulnerability found in their Office product vis support.
- 2020-08-25 - Vendor acknowledge however they're asking to send the report via support (LOL). I follow up with them if they have vulnerability disclosure processes.
- 2020-08-26 - Vendor informed us they said they have bug bounty and proper processes. 
- 2020-09-04 - Submit report to vendor 
- 2020-09-07 - Follow up with vendor
- 2020-09-10 - Vendor respond saying that "there are issues in setting the memory allocation range, but in actual practice, Hancom Office's dynamic detection security function would automatically stop any exploit of such vulnerabilities and malicious behavior at the point of occurrence. In other words, the blocking function would trigger to prevent any actual damage.". My response to them is when I did fuzzing on their application, my fuzzer several crashes that actually caught by the dynamic detection memory by Hancom Word. Hancom actually integrating some anti-exploit DLL (BitSentry) to actually works on the memory allocation. However on some of the other cases manage to bypass this anti-exploit and able to trigger Out-of-Bounds. 
- 2020-09-17 - Vendor responding they will work on the issue that has reported.
- 2020-09-24 - Follow up with vendor
- 2020-09-29 - Vendor responding the bounty from KISA is not eligible for foreigner. I'm good with it as long as they fix the issue.
- 2020-09 until 2020-12 - No more updates from vendor
- 2021-01-15 - Follow up with vendor
- 2021-05-26 - No more update from vendor. Public writeup release (considering it 0-day), request for CVE.
