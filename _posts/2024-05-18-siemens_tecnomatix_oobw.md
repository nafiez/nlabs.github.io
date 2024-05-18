---
layout: post
title:  "CVE-2024-23803 - Siemens Tecnomatix Plant Simulation Out-of-Bounds Write Vulnerability"
date:   2024-05-18 10:00:00 +0800
tags:
    - CVE-2024-23803
    - SSA-017796
---

Overview
-----------
Siemens Tecnomatix Plant Simulation allows to model, simulate, visualize and analyze production systems and logistics processes to optimize material flow and resource utilization for all levels of your plant planning, from global facilities and local plants to specific production lines. 

- Build and visualize in 3D using included libraries or external CAD data. Leverage the JT data format for 3D modeling and Siemens direct model technology for efficient loading and realistic visualization of large 3D simulation models without compromising simulation and analysis needs.
- Handle, understand and maintain complex and detailed simulations much better than conventional simulation tools due to the architectural advantages of encapsulation, inheritance and hierarchy.
- Leverage an open system architecture to support multiple interfaces and integration capacities, including ActiveX, C, CAD, COM, JSON, MQTT, ODBC, OPCClassic, OPCUA, Oracle SQL, Socket and XML.
- Use experiment management tools and integrated neural networks to enable comprehensive experiment handling and automated system optimization via genetic algorithms.

Exact product that was found to be vulnerable including complete version information was Siemens Tecnomatix Plant Simulation 2302.0004 (Build 2817). The affected application contains an out of bounds write past the end of an allocated buffer while parsing a specially crafted SPP file. This could allow an attacker to execute code in the context of the current process. If a user is tricked to open the malicious SPP file with the affected products, this could lead the application to crash or potentially lead to arbitrary code execution.


Understanding Siemens File Format - Reverse Engineering JT File Format
----------------------------------------------------------------------
The SPP file format are almost identical to Microsoft Office Word Document file format. It uses ZIP library to compress the compile SPP program from the Siemens Plant Simulation software. The structure of the SPP file can be view using 7-zip (or any ZIP program):

![1](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture1.png)

The file signature of the SPP file starts with the magic bytes **D0 CF 11 E0 A1 B1 1A E1**. These magic bytes are known as Object Linking and Embedding (OLE) Compound File (CF) (OLECF) file format, known as Compound Binary File format by Microsoft, used by Microsoft Office 97-2003 applications. 

![2](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture2.png)

Then navigating to the next bytes in the SPP file format shows the strings of **Tecnomatix AESOP GmbH & Co KG**. 

![3](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture3.png)

The actual SPP file format is basically relying on the Siemens JT file format. **Jupiter Tessellation (JT)** file format is an openly-published ISO-standardized 3D CAD data exchange format used for product visualization, collaboration, digital mockups and other purposes. This file format is developed by Siemens. 

JT files are used in product lifecycle management (PLM) software programs and their respective CAD systems, by engineers and other professionals that need to analyze the geometry of complex products. The format and associated software are structured so that extremely large numbers of components can be quickly loaded, shaded and manipulated in real-time. Because all major 3D CAD formats are supported, a JT assembly can contain a mixture of any combination which has led to the term "multi-CAD". As JT is typically implemented as an integral part of a PLM solution, the resulting multi-CAD assembly is managed such that changes to the original CAD product definition files can be automatically synchronized with their associated JT files resulting in a multi-CAD assembly that is always up-to-date.

JT file structure consists of three (3) sequence of blocks / segments. These segments including File Header, TOC Segment and Data Segment. The File Header block is always the first block of data file in the file. The TOC Segment is located within the file using data stored in the File Header. Within the TOC Segment is information that locates all other Data Segments within the file. Although there are no JT format compliance rules about where the TOC Segment must be located within the file, in practice the TOC Segment is typically located either immediately following the File header or at the very end of the file following all other Data Segments.

![4](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture4.png)

The File Header is always the first block of data in a JT file. The File Header contains information about the JT file version and TOC location, which Loaders use to determine how to read the file. The exact contents of the File Header are as follows:

![5](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture5.png)

An 80-character version string defining the version of the file format used to write this file. The Version string has the following format, Version M.n Comment.

Where M is replaced by the major version number, n is replaced by the minor version number, and Comment provides other unspecified reserved information. The string with the following format is commonly used as Comment to indicate the DM library version that was used to write this JT file, **DM Maj.Min.Qrm.Irm**. Where Maj, Min, Qrm, and Irm are replaced by the major, minor, QRM, and IRM numbers respectively. The version string is padded with spaces to a length of 75 ASCII characters and then the final five characters must be filled with the following linefeed and carriage return character combination (shown using c-style syntax): 

![6](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture6.png)

These final 5 characters (shown above and referred to as ASCII/binary translation detection bytes) can be used by JT file readers to validate that the JT files has not been corrupted by ASCII mode FTP transfers. As an example, the JT Version 9.5 file written by DM library version 7.3.4.0 and the string will look as follows:

![7](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture7.png)

In our SPP file, the actual UChar:Version File Header look like this (80 bytes):

![8](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture8.png)

Next File Header structure contain the UChar:Byte Order. This defines the file byte order and thus can be used by the loader to determine if there is a mismatch (thus byte swapping required) between the file byte order and the machine (on which the loader is being run) byte order. Valid values for Byte Order are: 
- 0 – Least Significant byte first (LsbFirst) 
- 1 – Most Significant byte first (MsbFirst)

The TOC Segment contains information identifying and locating all individually addressable Data Segments within the file.  TOC Segment is always required to exist somewhere within a JT file. The actual location of the TOC Segment within the file is specified by the File Header segments "TOC Offset" field. The TOC Segment contains one TOC Entry for each individually addressable Data Segment in the file. Segment Header contains information that determines how the remainder of the Segment is interpreted by the loader. Segment Type defines a broad classification of the segment contents. For example, a Segment Type of **1** denotes that the segment contains Logical Scene Graph material; **2** denotes contents of a B-Rep, etc. The column labeled "ZLIB Applied?" denotes whether ZLIB compression is conditionally applied to the entirety of the segment's Data payload.

![9](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture9.png)

Segment Types 7-16 all identify the contents as LOD Shape data, where the increasing type number is intended to convey some notion of how high an LOD the specific shape segment represents. The lower the type in this 7-16 range the more detailed the Shape LOD. For the rare case when there are more than 10 LODs, LOD9 and greater are all assigned Segment Type 16. The more generic Shape Segment type is used when the Shape Segment has one or more of the following characteristics: 
•	Not a descendant of an LOD node
•	Is referenced by more than one LOD node
•	Shape has its own built-in LODs
•	No way to determine what LOD a Shape Segment represents

Initial extraction of the ZLIB applied in the SPP file shows the indicator of magic bytes **0x1F 0x8B**. These are the magic bytes of ZLIB header. Individual data fields of an Element data collection (and its children data collections) may have advanced compression/encoding applied to them as indicated through compression related data values stored as part of the particular Element’s storage format. In addition, another level of compression for example, ZLIB compression that may be conditionally applied to all bytes of information stored for all Elements within a particular Segment.

![10](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture10.png)


Vulnerability Discovery via Fuzzing
-----------------------------------
During fuzzing, we use the theory Hamming Distance to calculate between two different files, original and fuzzed file using technique byte mutational. Hamming Distance is a function on words of fixed length over an alphabet describing the number of changes to the symbols of one word required to reduce it to another. Let A be an alphabet of symbols and C a subset of An, the set of words of length n over A. Let u=(u1,…,un) and v=(v1,…,vn) be words in C. Following are the example of Hamming Distance in C programming:
```
#include <iostream> 

using namespace std; 

int hammingDist(string str1, string str2) 
{ 
    int i = 0, count = 0; 
    while (str1[i] != '\0') 
    { 
        if (str1[i] != str2[i]) 
            count++; 
        i++; 
    } 
    return count; 
} 

int main() 
{ 
    string str1 = "stringOne"; 
    string str2 = "stringTwo"; 

    cout << hammingDist(str1, str2); 
    
    return 0; 
}
```

Using the Hamming Distance technique, its pretty easy to apply for the mutational method to fuzz each of the bytes contained in the SPP file format. The alternative to generating random strings from scratch is to start with a given valid input, and then to subsequently mutate it. A mutation in this context is a simple string manipulation - say, inserting a (random) character, deleting a character, or flipping a bit in a character representation. This is called mutational fuzzing in contrast to the generational fuzzing techniques. Following are the quick example of [mutational engine](https://www.fuzzingbook.org/html/MutationFuzzer.html):
```
import random

def byte_flipping(s):
    if s == "":
        return s
    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    bit = 1 << random.randint(0, 6)
    new_c = chr(ord(c) ^ bit)
    return s[:pos] + new_c + s[pos + 1:]

seed_input = "strings"
for i in range(10):
    x = byte_flipping(seed_input)
```

Following are the designed of the simple fuzzer used to fuzzed the Siemens Tecnomatix Plant Simulation software. The automated triage leverage the WinDBG command-line debugger called CDB.exe with the Exploitable plugin to determine the result of the crashes, and CERT BFF.

![12](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture12.png)

The fuzzing activity was executed for five (5) days with 102 crashes found. The stat results:

![13](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture13.png)

I used custom BFF CERT framework to analyzed the results and verify the findings. A quick investigation on one of the findings in the log result from the fuzzing activity:
```
start=12 min=12 target_guess=1 curr=6 chance=0.50000 miss=0/10 total_misses=0/1 u_crashes=0
testcase=0x796568be.0xaa312bce signal=None
start=12 min=12 target_guess=1 curr=8 chance=0.50000 miss=1/10 total_misses=1/2 u_crashes=1
testcase=0xa14d5fdf.0x6b2bb48e signal=None
Exhaustively checking remaining 8 bytes
testcase=0xe5ae2607.0x654c53de signal=None
testcase=0xe5ae2607.0xc784d66c signal=None
We were looking for [0xa14d5fdf.0x6b2bb48e] ...
    ...and found 0xe5ae2607.0x654c53de  6 times
    ...and found 0xa14d5fdf.0x6b2bb48e  1 times
    ...and found 0xe5ae2607.0xc784d66c  1 times
    ...and found 0x796568be.0xaa312bce  2 times
Bytemap: ['0x2a1c5', '0x16fccd', '0x22e11b', '0x2c05d8', '0x336ccf', '0x4da7b6', '0x50e5d6', '0x5a7be5']
```

The result from the above analysis is the one that are written in this article, covering the vulnerability analysis, reverse engineering and potential exploitation.


Vulnerability Analysis - Reverse Engineering the Root Cause
-----------------------------------------------------------
Tecnomatix Plant Simulation allows you to model, simulate, explore and optimize logistics systems and their processes. These models enable analysis of material flow, resource utilization and logistics for all levels of manufacturing planning from global production facilities to local plants and specific lines, well in advance of production execution. 

This vulnerability is present in the Siemens Tecnomatix Plant Simulation which is used among other things to model, simulate, explore and optimize logistics systems and their processes. A specially crafted SPP file can lead to a heap corruption and ultimately to remote code execution. The vulnerability was found during fuzzing the SPP file. The crash trigger after several hours of fuzzing activity executed. From the fuzzing result:
```
(11f8.548): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
PlantSimCore!IModelfstream::getKeyword+0x5c:
00007ffa`ea1f436c 880f            mov     byte ptr [rdi],cl ds:00000000`01791000=??
```

Quick analysis on the final crash path shows the RDI being accessed by CL register via bytes. We take a look into the crash path with IDA Pro to observed the behavior code. 
```
.text:0000000180835831                 mov     rax, [rbx]
.text:0000000180835834                 movzx   ecx, byte ptr [rax]
.text:0000000180835837                 cmp     cl, 20h ; ' '
.text:000000018083583A                 jbe     short loc_180835846
.text:000000018083583C                 mov     [rdi], cl
.text:000000018083583E                 inc     rdi
.text:0000000180835841                 inc     qword ptr [rbx]
.text:0000000180835844                 jmp     short loc_180835831
.text:0000000180835846                 cmp     rax, [rbx+8]
.text:000000018083584A                 jnz     short loc_180835856
.text:000000018083584C                 mov     rcx, rbx        ; this
.text:000000018083584F                 call    ?nextReadBufferBlock@IModelfstream@@IEAAXXZ ; IModelfstream::nextReadBufferBlock(void)
.text:0000000180835854                 jmp     short loc_180835831
```

At the offset **0000000180835837**, we can see the CL register is being compare with 0x20. These bytes being parse and check after executing the Plant Simulation software with the malformed SPP file as our input. These bytes later being check if the size **0x20** are below or equal with the input file (location that being parse). The offset **0000000180835831**, stored the pointer contain in the RBX to the RAX and from the RAX, it takes each byte from the pointer of RAX to stored as smallest in the ECX register.

If the CL register below the offset size **0x20**, it jumps to the offset **0000000180835846**. This code does some slim read / write (SRW) locks that will enable threads of a single process to access shared resources, which will be optimized for speed and occupy very little memory. 
```
.text:0000000180835846                 cmp     rax, [rbx+8]
.text:000000018083584A                 jnz     short loc_180835856
.text:000000018083584C                 mov     rcx, rbx
.text:000000018083584F                 call    sub_180835580
.text:0000000180835854                 jmp     short loc_180835831
```

According to Microsoft, SRW does:
```
Reader threads read data from a shared resource whereas writer threads write data to a shared resource. When multiple threads are reading and writing using a shared resource, exclusive locks such as a critical section or mutex can become a bottleneck if the reader threads run continuously but write operations are rare.
```

If we investigate the offset **000000018083584F**, the function does call the AcquireSRWLockExclusive, it grants read/write access to one writer thread at a time. When the lock has been acquired in exclusive mode, no other thread can access the shared resource until the writer releases the lock. Exclusive mode SRW locks cannot be acquired recursively. If a thread tries to acquire a lock that it already holds, that attempt will fail or deadlock. 

A single SRW lock can be acquired in either mode; reader threads can acquire it in shared mode whereas writer threads can acquire it in exclusive mode. There is no guarantee about the order in which threads that request ownership will be granted ownership; SRW locks are neither fair nor FIFO. An SRW lock is the size of a pointer. The advantage is that it is fast to update the lock state. The disadvantage is that very little state information can be stored, so SRW locks do not detect incorrect recursive use in shared mode. In addition, a thread that owns an SRW lock in shared mode cannot upgrade its ownership of the lock to exclusive mode. In this case, we know that the SRW lock is the size of the pointer that are held in RDI register. Assuming the RDI size is not define, when CL trying to access the out-of-memory memory range, it could trigger overflow. But how do we know what type overflow happen here? We have to trace back to the original code that are called before the crash trigger.

Investigating the code in reverse way allows us to understand more on what is happening in the code. Before it calls to the function **sub_1808357E0**, it supposed to check for the ANI object. ANI object in this context is the image that are use as part of the embedded image file format in the Plant Simulation software. The register RCX are use to stored all the information of the ANI object (initially from the pointer). We can verify this from the offset **0000000180066952**. It expects the size of the pointer block are maximize to **0xFFFF0000 (65535)**.
```
.text:0000000180066952         mov     dword ptr [rcx+0Ch], 0FFFF0000h
.text:0000000180066959         mov     [rcx], r12
.text:000000018006695C         mov     r14, rcx
.text:000000018006695F         mov     [rcx+8], r12d
.text:0000000180066963         mov     r13, r8
.text:0000000180066966         mov     [rcx+10h], r12
.text:000000018006696A         mov     rbx, rdx
.text:000000018006696D         mov     rcx, rdx
.text:0000000180066970         call    sub_1808357E0    ; crash trigger call here
.text:0000000180066975         mov     rcx, rax
.text:0000000180066978         lea     rdx, aAniobject  ; "aniObject"
.text:000000018006697F         call    sub_18082BDE0
.text:0000000180066984         test    eax, eax
.text:0000000180066986         jz      short loc_1800669A6
.text:0000000180066988         lea     rcx, aAniobjectExpec ; "AniObject expected.\n"
.text:000000018006698F         call    sub_18018FA90
```

As we know the size of the block bytes are allocated, we have to trace back to the original code that are used to allocate all of the bytes. The function below is responsible to allocate the heap for ANI object parsing. Starting from the offset **0000000180667BFF** until **0000000180667C2D**, it allocates the heap object properly and then it reads the SPP file later. Then from the offset **0000000180667C39**, it calls the function **sub_180066940**. 
```
.text:0000000180667BF7                 mov     rcx, rbx
.text:0000000180667BFA                 call    sub_180835880
.text:0000000180667BFF                 mov     [r13+10h], ax
.text:0000000180667C04                 test    ax, ax
.text:0000000180667C07                 jz      short loc_180667C47
.text:0000000180667C09                 mov     rcx, cs:hHeap   ; hHeap
.text:0000000180667C10                 xor     edx, edx        ; dwFlags
.text:0000000180667C12                 movzx   eax, ax
.text:0000000180667C15                 lea     rdi, [rax+rax*2]
.text:0000000180667C19                 shl     rdi, 3
.text:0000000180667C1D                 mov     r8, rdi         ; dwBytes
.text:0000000180667C20                 call    cs:__imp_HeapAlloc
.text:0000000180667C26                 mov     rsi, rax
.text:0000000180667C29                 mov     [r13+8], rax
.text:0000000180667C2D                 add     rdi, rax
.text:0000000180667C30                 mov     r8, r12
.text:0000000180667C33                 mov     rdx, rbx
.text:0000000180667C36                 mov     rcx, rsi
.text:0000000180667C39                 call    sub_180066940
.text:0000000180667C3E                 add     rsi, 18h
.text:0000000180667C42                 cmp     rsi, rdi
.text:0000000180667C45                 jnz     short loc_180667C30
```

The code functionality allows us to assume that the ANI object being parse while the object has been specifically allocated with heap block chunk that uses the SRW to prevent abuse on the heap blocks however due to the out-of-bounds memory error when parsing the heap object due to the overflow on the heap, we manage to trigger heap corruption.
```
.text:0000000180667BF7 loc_180667BF7:                          ; CODE XREF: SimpleImage::SimpleImage(IModelfstream &,MultIcon &)+156↑j
.text:0000000180667BF7                 mov     rcx, rbx        ; this
.text:0000000180667BFA                 call    ?getRepeat@IModelfstream@@QEAAHXZ ; IModelfstream::getRepeat(void)
.text:0000000180667BFF                 mov     [r13+10h], ax
.text:0000000180667C04                 test    ax, ax
.text:0000000180667C07                 jz      short loc_180667C47
.text:0000000180667C09                 mov     rcx, cs:?hFastMallocHeap@@3PEAXEA ; hHeap
.text:0000000180667C10                 xor     edx, edx        ; dwFlags
.text:0000000180667C12                 movzx   eax, ax
.text:0000000180667C15                 lea     rdi, [rax+rax*2]             ; // times with 0x24 (example: v20 = 0x8000, then times with 0x24, 0x8000 * 0x24 = 0x120000, v21 = 0x120000)
.text:0000000180667C19                 shl     rdi, 3                       ; // 
.text:0000000180667C1D                 mov     r8, rdi         ; dwBytes
.text:0000000180667C20                 call    cs:__imp_HeapAlloc           ; // allocate a block of memory from a heap, number of bytes assigned from RDI and stored in R8
.text:0000000180667C26                 mov     rsi, rax             
.text:0000000180667C29                 mov     [r13+8], rax                 ; // copy bytes from the address pointed to by RAX into address pointed to by
.text:0000000180667C2D                 add     rdi, rax                     ; // element of the array
.text:0000000180667C30
.text:0000000180667C30 loc_180667C30:                          ; CODE XREF: SimpleImage::SimpleImage(IModelfstream &,MultIcon &)+1C5↓j
.text:0000000180667C30                 mov     r8, r12         ; struct MultIcon *
.text:0000000180667C33                 mov     rdx, rbx        ; struct IModelfstream *
.text:0000000180667C36                 mov     rcx, rsi        ; this
.text:0000000180667C39                 call    ??0AniObject@@QEAA@AEAVIModelfstream@@AEAVMultIcon@@@Z ; AniObject::AniObject(IModelfstream &,MultIcon &)
.text:0000000180667C3E                 add     rsi, 18h                     ; // ANI object parsing, heap allocation
.text:0000000180667C42                 cmp     rsi, rdi
.text:0000000180667C45                 jnz     short loc_180667C30
```

Offset **0000000180667BFA** will call the function **sub_180835880**, and this function basically parse for the bytes **0x20** and **0x7B**. These are the bytes it tries to parse inside the SPP file format that contain an ANI object. If these are not present, it does the check again based on the initial analysis from this document. The program does multiple checks to verify the integrity of the object and the sizing of the object that might meet the criteria as part of the file formatting.
```
.text:0000000180835880                 mov     [rsp+arg_0], rbx
.text:0000000180835885                 push    rdi
.text:0000000180835886                 sub     rsp, 20h
.text:000000018083588A                 mov     rbx, rcx
.text:000000018083588D                 call    sub_180835E50
.text:0000000180835892                 mov     rdx, [rbx]
.text:0000000180835895                 mov     edi, eax
.text:0000000180835897                 cmp     byte ptr [rdx], 20h ; ' '
.text:000000018083589A                 jnz     short loc_1808358CE
.text:000000018083589C                 inc     rdx
.text:000000018083589F                 mov     [rbx], rdx
.text:00000001808358A2                 cmp     rdx, [rbx+8]
.text:00000001808358A6                 jnz     short loc_1808358B0
.text:00000001808358A8                 mov     rcx, rbx
.text:00000001808358AB                 call    sub_180835580
.text:00000001808358B0                 mov     rax, [rbx]
.text:00000001808358B3                 cmp     byte ptr [rax], 7Bh ; '{'
.text:00000001808358B6                 jnz     short loc_1808358CC
.text:00000001808358B8                 inc     rax
.text:00000001808358BB                 mov     [rbx], rax
.text:00000001808358BE                 cmp     rax, [rbx+8]
.text:00000001808358C2                 jnz     short loc_1808358CC
.text:00000001808358C4                 mov     rcx, rbx
.text:00000001808358C7                 call    sub_180835580
```

Exploit Dev??? : Reconstructing the Proof-of-Concept
----------------------------------------------------
The memory bytes containing out-of-bounds memory range. The offset **00000086`31f90000** basically stored in RDI register that are pointing to the pointer out of nowhere / unknown memory range. When CL trying to access to this memory range, it starts to read somewhere that are unusual memory range. This memory range basically came from the heap allocated however when it exceeded the range that it has allocated in the ANI object, it could trigger overflow via out-of-bounds heap memory error. If we deducted with 0x10 bytes from the heap pointer, we could get the final strings that it parses before heap corruption triggered. 
```
0:000> dc 00000086`31f90000 - 0x10
00000086`31f8fff0  54304c53 54304c53 6f6f6f6f 354c5f65  SL0TSL0Tooooe_L5
00000086`31f90000  ???????? ???????? ???????? ????????  ????????????????
00000086`31f90010  ???????? ???????? ???????? ????????  ????????????????
00000086`31f90020  ???????? ???????? ???????? ????????  ????????????????
00000086`31f90030  ???????? ???????? ???????? ????????  ????????????????
00000086`31f90040  ???????? ???????? ???????? ????????  ????????????????
00000086`31f90050  ???????? ???????? ???????? ????????  ????????????????
00000086`31f90060  ???????? ???????? ???????? ????????  ????????????????
```

If we observed the registers, we could see the register RCX are set with 0x50. So, what is this 0x50 bytes and what it does? If we look into the parser from the earlier analysis, you could notice that the checks of the ANI objects bytes are **0x20** and **0x7B**. CL register is the lowest value it takes from the range of registers and when it compares those value **0x20** with **0x50**, it then exceeded the range of the bytes it parses. 
```
0:000> r
rax=0000008631f8fda2 rbx=0000008631f2f3d0 rcx=0000000000000050
rdx=0000000000000014 rsi=00007ff8609a0000 rdi=0000008631f90000
rip=00007ff8611d583c rsp=0000008631f2e750 rbp=0000027d2c036e20
 r8=0000027d73181ff0  r9=0000027d2c036e20 r10=0000000000000000
r11=0000000000000246 r12=0000000000000000 r13=0000000000000000
r14=0000008631f2f3e1 r15=0000027d2c020e01
iopl=0         nv up ei pl nz na po nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010206
```

The bytes of 0x50 are already off the heap range:
```
0:000> dc cl
00000000`00000050  ???????? ???????? ???????? ????????  ????????????????
00000000`00000060  ???????? ???????? ???????? ????????  ????????????????
00000000`00000070  ???????? ???????? ???????? ????????  ????????????????
00000000`00000080  ???????? ???????? ???????? ????????  ????????????????
00000000`00000090  ???????? ???????? ???????? ????????  ????????????????
00000000`000000a0  ???????? ???????? ???????? ????????  ????????????????
00000000`000000b0  ???????? ???????? ???????? ????????  ????????????????
00000000`000000c0  ???????? ???????? ???????? ????????  ????????????????
```

Following are the result from stack trace:
```
0:000> kvL
 # Child-SP          RetAddr               : Args to Child                                                           : Call Site
00 00000086`31f2e750 00007ff8`60c9394f     : 00007ff8`609a0000 00000086`31f2f3d0 00007ff8`61614a08 00007ff8`60c80000 : PlantSimCore!IModelfstream::getKeyword+0x5c
01 00000086`31f2e780 00007ff8`6100ffa6     : 0000027d`2c036e20 0000027d`2c036e20 0000027d`2c036e00 00000086`31f20000 : PlantSimCore!MatCarrier::readFrom+0x3f
02 00000086`31f2e800 00007ff8`60e27a8b     : 0000027d`2c036e20 00000086`31f2f3e1 0000027d`2c020eb0 00000000`00000000 : PlantSimCore!SingleCarrier::readFrom+0xe6
03 00000086`31f2e830 00007ff8`60d12c2e     : 00000000`00000000 00000086`31f2f3d0 00000086`31f2f3e1 00000086`31f2f3d0 : PlantSimCore!CarrierRegistry::testread+0xeb
04 00000086`31f2e860 00007ff8`60f7728a     : 00007ff8`613aa6c8 00000086`31f2f3d0 00000000`00000003 00007ff8`61390000 : PlantSimCore!Node::readFrom+0x9e
05 00000086`31f2e8d0 00007ff8`60e27687     : 0000027d`2c020eb0 0000027d`7b6a4fe0 0000027d`2be7af20 0000027d`77aedff0 : PlantSimCore!Place::readFrom+0x6a
06 00000086`31f2e900 00007ff8`60e210ac     : 0000027d`2bff8eb0 00000086`31f2f3d0 00000086`31f2f3e1 0000027d`2be70000 : PlantSimCore!NwObjRegistry::testread+0x137
07 00000086`31f2e930 00007ff8`60e27687     : 0000027d`2be7af20 0000027d`2be7af20 00000086`31f2f3e1 0000027d`7a502fe0 : PlantSimCore!NwObjFolder::readFrom+0x16c
08 00000086`31f2e970 00007ff8`60e210ac     : 0000027d`2bdc0f20 00000086`31f2f3d0 00000086`31f2f3e1 0000027d`7d240000 : PlantSimCore!NwObjRegistry::testread+0x137
09 00000086`31f2e9a0 00007ff8`60f07c95     : 00000086`31f2f3d0 00000086`31f2f3d0 00000086`31f2f3e1 00007ff8`6163ee78 : PlantSimCore!NwObjFolder::readFrom+0x16c
0a 00000086`31f2e9e0 00007ff8`60d89d38     : 00000000`0000000f 00000086`31f2ebb0 0000027d`7d248f20 00000086`31f2ea70 : PlantSimCore!Palete::readFrom+0x2a5
0b 00000086`31f2ea30 4c5f3440`50303440     : 54304c53`54305035 6f6f6f6f`54304c53 53543050`354c5f65 6f54304c`5354304c : PlantSimCore!OpenModel+0xe98
0c 00000086`31f8f590 54304c53`54305035     : 6f6f6f6f`54304c53 53543050`354c5f65 6f54304c`5354304c 50354c5f`656f6f6f : 0x4c5f3440`50303440
0d 00000086`31f8f598 6f6f6f6f`54304c53     : 53543050`354c5f65 6f54304c`5354304c 50354c5f`656f6f6f 4c535430`4c535430 : 0x54304c53`54305035
```

Given an out-of-bounds memory write primitive like the vulnerability we discovered, there’s now a highly standard way of exploiting the **Siemens Tecnomatix Plant Simulation** software. One way to do this is to simply apply the heap grooming technique to arrange for the pointer we control on the ANI buffer object to follow the object which the write goes off the end of. The errant write will then clobber the length of the ANI object, resulting in the ability to read and write arbitrary process memory past the end of the heap allocator. Illustration of the exploitation vector that are applicable in the context of the heap corruption:

![14](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/Picture14.png)

Windows 10 requires a different way to groom the heap allocation, and it is slightly more complicated than the OSes before. Low fragmentation heap is a way to allow the system to allocate memory in certain predetermined sizes. It means when the application asks for an allocation, the system returns the minimum available chunk that fits. This sounds really nice, except on Windows 10, it also tends to avoid giving you a chunk that has the same size as its neighbor.  For this exploitation scenario, the most important objective for our heap overflow is to overwrite the heap allocation length. It is more than enough to read past the allocated heap size and collect data in the next chunk.

Disclosure timeline
-------------------
The vulnerability was reported back in November 2023. Timeline of disclosure:
- [November 29, 2023] Sending the proof-of-concept and the analysis to productcert@siemens.com
- [December 12, 2023] Siemens CERT team acknowledge teh submission and track the submission with ID S-PCERT#76836
- [February 13, 2024] Siemens CERT sending an email regarding the advisory on https://cert-portal.siemens.com/productcert/html/ssa-017796.html
