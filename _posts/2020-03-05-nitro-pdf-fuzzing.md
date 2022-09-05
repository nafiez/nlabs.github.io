---
layout: post
title:  "Nitro Pro 13 - From Fuzzing to Multiple Heap Corruption (CVE-2020-10222 & CVE-2020-10223)"
date:   2020-03-05 18:00:03 +0800
categories: 
  - vulnerability
  - fuzzing
---

Introduction
------------
Last December, I decided to continue fuzzing on Nitro PDF software. I wrote a harness for Nitro PDF reader and fuzzing it with WinAFL. While writing and debugging (try and error lol) the issue for my harness, I plan to run another fuzzer which is CERT Basic Fuzzing Framework (BFF) and let it run for few couple of days just to see if there's any bug or crashes found. CERT BFF is a software-testing tool that performs mutational fuzzing on software that consumes file input. Mutational fuzzing is the act of taking well-formed input data and corrupting it in various ways, looking for cases that cause crashes. The BFF automatically collects test cases that cause software to crash in unique ways, and debugs information associated with the crashes.

TLDR; after few hours running, BFF caught some exceptions and there's a bunch of issue found. 

Vulnerability Description
-------------------------
Nitro Software, Inc. develops commercial software used to create, edit, sign, and secure Portable Document Format files and digital documents. The company has over 650,000 business customers worldwide, and claims millions of users across the globe. However, the code behind the Nitro uses famous library known JBIG2Decode. Affected version are 13.8.2.140. I believe the version below 13.8.2.140 are affected too, but haven’t tested until this time.

Fuzzing with BFF
----------------
I setup the environment in VM using Windows 10 x64 with BFF tool along with the Nitro Pro 13 version 13.8.2.140. The BFF tool can be downloaded from [here](https://resources.sei.cmu.edu/tools/downloads/vulnerability-analysis/bff/assets/BFF28/BFF-2.8-setup.zip). Its a installer and just click next and next until it gets installed at **C:\BFF**.

Fuzzing with BFF is not that hard like AFL and WinAFL where you need to write harness, compile with its specific APIs, having limitation with corpus size and many more. BFF uses configuration file in a YAML format and allows user to modify the options and they call it fuzzing campaign settings. The options including:
```
- "campaign" name (project / target name)
- "target" installation path (executable location to fuzz)
- "directories" for store the seed files (corpus) and results
- "runner" supports the timeout of the application executed, watch CPU process and hide stdout of the application
- "debugger" sets a debugging heap and number of exceptions being handled
- "runoptions" supports iteration, seed interval, minimize crashes, recycle crashses and check for duplicates
- "fuzzer" where it supports multiple type of built-in fuzzer including bytemut, swap, wave, drop, insert, truncate, crmut, crlfmut, nullmut, verify
```

I select **byte mutation (bytemut)** option in the config file and once the BFF run, it will load the module bytemut.py. According to CERT, the module randomly selects bytes in an input file and assign random values. The percent of the selected bytes can be tweaked by min_ratio and max_ratio. It is roughly similar to Charlie Miller's 5 lines of [Python](http://flatlinesecurity.com/posts/charlie-miller-five-line-fuzzer/). 
The CERT team has more explanation [here](https://vuls.cert.org/confluence/display/tools/CERT+BFF+-+Basic+Fuzzing+Framework).

Once all setup properly, just fire up the file called **bff.py** in command prompt and it should initialize the first running as in following screenshot:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/bff_1.png "Screenshot broadcast")

It then build the seedfile set and run the program.
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/bff_2.png "Screenshot broadcast")

After few hours of running, there are 111 crashes found. Amongst this hundreds crashes, it was only categorized as **UNKNOWN** and **PROBABLY_NOT_EXPLOITABLE**. There's no **EXPLOITABLE** was caught during fuzzing. 

**UNKNOWN Results** 
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/crash_file.png "Screenshot broadcast")

**PROBABLY_NOT_EXPLOITABLE Results**
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/crash_file_2.png "Screenshot broadcast")

Looking at the **UNKNOWN** results it tells us a lot of duplicates and required to manually triaging those crash path. Since BFF supports minimization, it helps a lot in speed up the analysis by viewing the **MSEC** log file. This log contains the crash dump of the program (on the last state of exception) and provide the result of exploitability based on Microsoft Exploitable plugin for WinDBG. Below are the example of **MSEC** log file.

Crash dump:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/crash_data.png "Screenshot broadcast")

Exploitability result:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/exploitability_result.png "Screenshot broadcast")

After eliminating the duplicates, I look for a unique crash dump. What I'm looking for was a result with following pattern:
```
- TaintedDataControlsBranchSelection
- TaintedDataReturnedFromFunction
```

At least this pattern gives a bit hope whne looking into the crash dump. I just filter out things using command prompt **findstr** with the following pattern. Here's an example result:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/filter_.png "Screenshot broadcast")

There's a number of interesting crash dump, example:
```
- Exception at npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x12fbe
(afc.1be0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Nitro\Pro\13\npdf.dll - 
npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x12fbe:
00007ffe`cc165bbe 4c8b1cc1        mov     r11,qword ptr [rcx+rax*8] ds:0000014f`d6680078=????????????????

- Exception at npdf!nitro::get_property+0x23e0
(212c.1918): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Nitro\Pro\13\npdf.dll - 
npdf!nitro::get_property+0x23e0:
00007ffe`cc6b7a80 488b5708        mov     rdx,qword ptr [rdi+8] ds:f0f0f0f0`f0f0f0f8=????????????????
```

Here we can see BFF are doing a good job by identifying unique issue in the target software. I randomly pick the crash dump and start to analyze it. In this writeup, I put two interesting issue which is both are heap corruption vulnerability. 


(CVE-2020-10223) Vulnerability 1 - JBIG2Decode CNxJBIG2DecodeStream Heap Corruption Vulnerability
--------------------------------------------------------------------------------------------------
An exploitable heap corruption vulnerability exists in the handling of JBIG2Decode object stream attributes of Nitro PDF Reader version 13.8.2.140. A specially crafted PDF document can trigger a heap corruption, which can disclose sensitive memory content and aid in exploitation when coupled with another vulnerability. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability. The exception happened on the npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x12fbe.

The heap corruption issue found when it parse the JBIG2Decode stream, where it failed to decode the unicode character found in the stream. This happened when it tries to process the following proof-of-concept:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/pdf_.png "Screenshot broadcast")

When opened the POC with PDF reader (attach with debugger), the reader will prompt for an error to open the file. Thus, an exception trigger in debugger. 
```
(138.d90): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Nitro\Pro\13\npdf.dll - 
npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x12fbe:
00007fff`a1235bbe 4c8b1cc1        mov     r11,qword ptr [rcx+rax*8] ds:000001f9`ab650098=????????????????
```

Stack trace from our debugger:
```
000000f2`2a1f9e80 00007fff`a123508a : 000000f2`2a1fa370 000000f2`2a1fa370 00000000`00000000 00000001`a126b780 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x12fbe
000000f2`2a1f9fe0 00007fff`a12341d4 : 000000f2`2a1fa370 000000f2`2a1fa370 00000000`00000000 00000000`00000013 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x1248a
000000f2`2a1fa1f0 00007fff`a122d88f : 00000000`00000000 000001f9`00000002 000001f9`00000022 00007fff`a123d4b7 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x115d4
000000f2`2a1fa260 00007fff`a122d083 : 000000f2`2a1fa370 000000f2`2a1fa370 000000f2`2a1fa6d0 00000000`00000001 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0xac8f
000000f2`2a1fa2b0 00007fff`a122d937 : 00007fff`a14f4d23 00007fff`a1172950 00000000`000000ab 00000000`00000000 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0xa483
000000f2`2a1fa330 00007fff`a123bd8e : 00000000`00000004 000000f2`2a1fa4c0 00000000`00000004 000001f9`9ddaacf0 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0xad37
000000f2`2a1fa4b0 00007fff`a123bb13 : 000001f9`9ddaacf0 000000f2`2a1fa579 000001f9`f7ab8fe0 000001f9`9ddaabb0 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x1918e
000000f2`2a1fa4f0 00007fff`a123b064 : 000001f9`9ddaae10 000001f9`ab299f50 00000000`00000002 00000000`00000002 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x18f13
000000f2`2a1fa5d0 00007fff`a123d725 : 000000f2`2a1fa6d0 00000000`00000000 00007fff`a1576230 00000000`0000e110 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x18464
000000f2`2a1fa690 00007fff`a123d62a : 00000000`00000004 00000000`00000002 000001f9`9ddaaab0 00000000`01000002 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x1ab25
000000f2`2a1fa7a0 00007fff`a123d3c5 : 00000000`00000000 00000000`00000002 000001f9`9ddaaab0 00007fff`a14f4d23 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x1aa2a
000000f2`2a1fa8b0 00007fff`a1172986 : 000001f9`96646fc0 000001f9`9ddaaab0 000001f9`96ef1e10 00000000`00000000 : npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x1a7c5
000000f2`2a1fa900 00007fff`a10cf2f5 : 000001f9`96646fc0 000001f9`96ef1e10 00000000`00000000 00000000`00000000 : npdf!CosStreamOpenStm+0x66
000000f2`2a1fa950 00007fff`a1069301 : 00000000`00000001 000000f2`2a1fe260 000000f2`2a1faac0 00007fff`be3547c8 : npdf!PDTextIsSpaceBetween+0xe7ba5
000000f2`2a1fa9c0 00007fff`a10dca87 : 00000000`00000000 000001f9`96ef1e10 000001f9`96ef1e10 00000000`00000000 : npdf!PDTextIsSpaceBetween+0x81bb1
000000f2`2a1fdc40 00007fff`a0fca8e3 : 000001f9`eca4efc0 000001f9`a7062e38 000001f9`ecbacdc0 00007fff`a0fa2fbb : npdf!PDTextIsSpaceBetween+0xf5337
000000f2`2a1fe440 00007fff`a0fc2390 : 000001f9`ecbacdc0 000001f9`96ef1e10 000001f9`ecbacdc0 000001f9`9ddaaab0 : npdf!init_npdf_optional_features+0x9a03
000000f2`2a1fe510 00007fff`a0fdee22 : 000001f9`ecbacdc0 00000000`00000000 000001f9`ecbacdc0 00080000`00100081 : npdf!init_npdf_optional_features+0x14b0
000000f2`2a1fe560 00007fff`a0fc97c0 : 000001f9`ecbacdc0 000001f9`ecbacdc0 000001f9`96f54f60 000001f9`96f54f60 : npdf!init_npdf_optional_features+0x1df42
000000f2`2a1fe640 00007fff`a11a780e : 000001f9`ecbacdc0 000001f9`f38d8fc0 000001f9`96946fb0 00007fff`d44c7dce : npdf!init_npdf_optional_features+0x88e0
000000f2`2a1fe750 00007fff`a11a8deb : 000000f2`2a1fedf0 00007fff`d5a648c9 000001f9`d9970c60 ffffffff`ce0113ac : npdf!PDOCMDsMakeContentVisible+0x9be
000000f2`2a1fe860 00007ff7`3572a1ed : 000001f9`e8e2ff40 00000000`00000000 00000000`00000000 00000000`00000470 : npdf!PDPageDrawContentsWithParamsEx+0x6b
000000f2`2a1fe8d0 00007ff7`3572f041 : 00007fff`a492a0f0 000000f2`000003fc 000001f9`fb43ff90 000000f2`2a1fedf0 : NitroPDF!CxIOFile::Write+0x680ed
000000f2`2a1febb0 00007fff`a486d5f8 : 000000f2`2a1fec60 00000000`00000008 000001f9`fb43f860 00000000`00000000 : NitroPDF!CxIOFile::Write+0x6cf41
000000f2`2a1fec30 00007fff`a4883473 : 00000000`0000011d 00000000`00000000 00000000`00000000 00000000`00000000 : mfc140u!CView::OnPaint+0x68
000000f2`2a1fecf0 00007fff`a4882d2f : 000001f9`fb43f860 00000000`00000000 00000000`00000000 00000000`00000000 : mfc140u!CWnd::OnWndMsg+0x703
000000f2`2a1fee70 00007fff`a48805ce : 00000000`00000000 000001f9`d515ee20 00000000`00000000 00000000`0000000f : mfc140u!CWnd::WindowProc+0x3f
000000f2`2a1feeb0 00007fff`a48809b4 : 00000000`0000000f 00000000`001505fe 000000f2`2a1ff008 00007fff`0000000f : mfc140u!AfxCallWndProc+0x12e
000000f2`2a1fefa0 00007fff`a4727841 : 00000000`00000000 00000000`001505fe 00000000`0000000f 00000000`00000000 : mfc140u!AfxWndProc+0x54
000000f2`2a1fefe0 00007fff`d5a4c906 : 00000000`00000001 000001f9`d515ee78 00000000`00000000 00000000`00000000 : mfc140u!AfxWndProcBase+0x51
000000f2`2a1ff030 00007fff`d5a4c62c : 00000000`00000388 00007fff`a47277f0 00000000`001505fe 00000000`80000000 : USER32!UserCallWinProcCheckWow+0x266
000000f2`2a1ff1b0 00007fff`d5a600a3 : 00000000`00000000 00000000`00000000 00000000`00000000 000001f9`d515ee78 : USER32!DispatchClientMessage+0x9c
000000f2`2a1ff210 00007fff`d83f3494 : 00000000`00000000 00000000`0017055e 000001f9`d1c87f50 00007fff`a48a02a5 : USER32!_fnDWORD+0x33
000000f2`2a1ff270 00007fff`d4461764 : 00007fff`d5a4c49f 0000a0ad`b423c9e8 00000000`00000000 000001f9`d515ee20 : ntdll!KiUserCallbackDispatcherContinue
000000f2`2a1ff2f8 00007fff`d5a4c49f : 0000a0ad`b423c9e8 00000000`00000000 000001f9`d515ee20 00007ff7`357788ce : win32u!NtUserDispatchMessage+0x14
000000f2`2a1ff300 00007fff`a48696d2 : 000001f9`d515ee78 00007fff`00000000 000001f9`d515ee78 00000000`00000000 : USER32!DispatchMessageWorker+0x22f
000000f2`2a1ff380 00007fff`a486a017 : 00000000`00000001 000001f9`d515ee78 00000000`00000000 000001f9`d515ee78 : mfc140u!AfxInternalPumpMessage+0x52
000000f2`2a1ff3b0 00007ff7`3577ab6a : 000001f9`ea2dffd0 00007ff7`356a0000 00000000`00000001 00000000`00000001 : mfc140u!CWinThread::Run+0x77
000000f2`2a1ff3f0 00007fff`a489c6c0 : 00000000`00000001 00000000`00000001 00000000`00000000 00000000`00010001 : NitroPDF!CxIOFile::Write+0xb8a6a
000000f2`2a1ffa00 00007ff7`358676f6 : 00000000`00000001 00000000`00000000 00000000`00000000 00000000`00000000 : mfc140u!AfxWinMain+0xc0
000000f2`2a1ffa40 00007fff`d6717974 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : NitroPDF!nitro::filenames_provider::workflow::get_from_program_data+0x4f8c6
000000f2`2a1ffa80 00007fff`d83ba271 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x14
000000f2`2a1ffab0 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21
```

The vulnerability lies at sub_180395650 function. This function basically performed a parsing the JBIG2 and decode the stream. The library named, CNxJBIG2DecodeStream. The analysis as in the following disassembly.

The first check, sub_18038E960 function act as parser and takes an argument. Our corrupted value lies here:
```
.text:000000018039595D                 test    r14, r14
.text:0000000180395960                 jz      short loc_18039597E
.text:000000018039597E                 mov     edx, [rbp+50h+arg_18]
.text:0000000180395984                 call    sub_18038E960                // perform some checking here, this function responsible to handle the allocation and free pointer
.text:000000018039597C                 jmp     short loc_1803959A4
.text:00000001803959A1                 mov     r14d, eax
.text:00000001803959A4                 cmp     r14d, dword ptr [rbp+50h+arg_8]
.text:00000001803959AB                 jb      short loc_1803959EB
```
Then it perform another check here:
```
.text:00000001803959AD                 mov     dword ptr [rsp+120h+var_F8], 996h
.text:00000001803959B5                 mov     [rsp+120h+var_100], rdi
.text:00000001803959BA                 xor     r9d, r9d
.text:00000001803959BD                 mov     r8d, 20040007h
.text:00000001803959C3                 lea     rdx, aJbig2decodeI_1 ; "JBIG2Decode: Invalid symbol number in J"...
.text:00000001803959CA                 mov     rcx, cs:off_1808A5F30
.text:00000001803959D1                 call    sub_1802EE190
.text:00000001803959D6                 mov     eax, [rbp+88h]
.text:00000001803959DC                 sub     eax, dword ptr [rsp+120h+var_C0]
.text:00000001803959E0                 cmp     eax, 800h
.text:00000001803959E5                 ja      loc_180395E65
```
Then it will decode the symbol resource index:
```
.text:0000000180395A72                 mov     r8, [rsi+0E0h]
.text:0000000180395A79                 lea     rdx, [rbp+50h+var_58]
.text:0000000180395A7D                 mov     rcx, [rsi+68h]
.text:0000000180395A81                 call    sub_18039CEA0
.text:0000000180395A86                 test    al, al
.text:0000000180395A88                 jz      loc_180395EA4
```

Last check was done from here. r8 is the corrupted pointer, the corrupted pointer isn't properly assign and the object is not free. 
```
.text:0000000180395AC7                 mov     r8, [rbp+50h+var_A8]     // r8 = 000000000000004c, 0x4c leads to corrupted pointer
.text:0000000180395ACB                 lea     rdx, [rbp+50h+var_5C]
.text:0000000180395ACF                 mov     rcx, [rsi+0F0h]          
.text:0000000180395AD6                 call    sub_18038E010
.text:0000000180395ADB                 test    al, al
.text:0000000180395ADD                 jz      short loc_180395B2C
```

An invalid passing of function pointer and thus a bad call to a function:
```
.text:0000000180395BB6                 mov     eax, r14d
.text:0000000180395BB9                 mov     rcx, [rsp+120h+var_A8]   // rcx = 000001bc2bf4b0a0
.text:0000000180395BBE                 mov     r11, [rcx+rax*8]         // crash here
.text:0000000180395BC2                 test    r11, r11
.text:0000000180395BC5                 jz      loc_180395E65
```

The Heap:
```
0:000> !heap -p -a @r11
    address 000001f9a6fa1ff0 found in
    _DPH_HEAP_ROOT @ 1f9d1961000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                             1f9f349c270:      1f9a6fa1ff0               10 -      1f9a6fa1000             2000
    00007fffd8456cf7 ntdll!RtlDebugAllocateHeap+0x000000000000003f
    00007fffd83fca9e ntdll!RtlpAllocateHeap+0x000000000009d23e
    00007fffd835da21 ntdll!RtlpAllocateHeapInternal+0x0000000000000991
    00007fffd531ca26 ucrtbase!_malloc_base+0x0000000000000036
    00007fffa14f4d23 npdf!nitro::notifications::notification_manager::DestroyNotification+0x0000000000297903
    00007fffa122cf2c npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x000000000000a32c
    00007fffa122d937 npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x000000000000ad37
    00007fffa123bd8e npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x000000000001918e
    00007fffa123bb13 npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x0000000000018f13
    00007fffa123b064 npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x0000000000018464
    00007fffa123d725 npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x000000000001ab25
    00007fffa123d62a npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x000000000001aa2a
    00007fffa123d3c5 npdf!CAPPDAnnotHandlerUtils::create_popup_for_markup+0x000000000001a7c5
    00007fffa1172986 npdf!CosStreamOpenStm+0x0000000000000066
    00007fffa10cf2f5 npdf!PDTextIsSpaceBetween+0x00000000000e7ba5
    00007fffa1069301 npdf!PDTextIsSpaceBetween+0x0000000000081bb1
    00007fffa10dca87 npdf!PDTextIsSpaceBetween+0x00000000000f5337
    00007fffa0fca8e3 npdf!init_npdf_optional_features+0x0000000000009a03
    00007fffa0fc2390 npdf!init_npdf_optional_features+0x00000000000014b0
    00007fffa0fdee22 npdf!init_npdf_optional_features+0x000000000001df42
    00007fffa0fc97c0 npdf!init_npdf_optional_features+0x00000000000088e0
    00007fffa11a780e npdf!PDOCMDsMakeContentVisible+0x00000000000009be
    00007fffa11a8deb npdf!PDPageDrawContentsWithParamsEx+0x000000000000006b
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Nitro\Pro\13\NitroPDF.exe - 
    00007ff73572a1ed NitroPDF!CxIOFile::Write+0x00000000000680ed
    00007ff73572f041 NitroPDF!CxIOFile::Write+0x000000000006cf41
    00007fffa486d5f8 mfc140u!CView::OnPaint+0x0000000000000068 [d:\agent\_work\1\s\src\vctools\VC7Libs\Ship\ATLMFC\Src\MFC\viewcore.cpp @ 186]
    00007fffa4883473 mfc140u!CWnd::OnWndMsg+0x0000000000000703 [d:\agent\_work\1\s\src\vctools\VC7Libs\Ship\ATLMFC\Src\MFC\wincore.cpp @ 2465]
    00007fffa4882d2f mfc140u!CWnd::WindowProc+0x000000000000003f [d:\agent\_work\1\s\src\vctools\VC7Libs\Ship\ATLMFC\Src\MFC\wincore.cpp @ 2099]
    00007fffa48805ce mfc140u!AfxCallWndProc+0x000000000000012e [d:\agent\_work\1\s\src\vctools\VC7Libs\Ship\ATLMFC\Src\MFC\wincore.cpp @ 265]
    00007fffa48809b4 mfc140u!AfxWndProc+0x0000000000000054 [d:\agent\_work\1\s\src\vctools\VC7Libs\Ship\ATLMFC\Src\MFC\wincore.cpp @ 417]
    00007fffa4727841 mfc140u!AfxWndProcBase+0x0000000000000051 [d:\agent\_work\1\s\src\vctools\VC7Libs\Ship\ATLMFC\Src\MFC\afxstate.cpp @ 299]
    00007fffd5a4c906 USER32!UserCallWinProcCheckWow+0x0000000000000266
```



(CVE-2020-10222) Vulnerability 2 - get_property Heap Corruption Vulnerability
-----------------------------------------------------------------------------
An exploitable heap corruption vulnerability exists in the handling of get_property function when parsing for object /binary stream of Nitro PDF Reader version 13.8.2.140. A specially crafted PDF document can trigger a heap corruption, which can disclose sensitive memory content and aid in exploitation when coupled with another vulnerability. An attacker needs to trick the user to open the malicious file to trigger this vulnerability. If the browser plugin extension is enabled, visiting a malicious site can also trigger the vulnerability. The exception happened on the npdf!nitro::get_property+2381 function.

The heap corruption issue found when it parsing the object stream (between object number and revision), where it failed to recognize additional bytes found in the stream. This happened when it tries to process the following proof-of-concept:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/1.png "Screenshot broadcast")

After open the POC with PDF reader (attach with debugger), the reader will prompt for an error to open the file. Thus, an exception trigger in debugger. 
```
(212c.1918): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Program Files\Nitro\Pro\13\npdf.dll - 
npdf!nitro::get_property+0x23e0:
00007ffe`cc6b7a80 488b5708        mov     rdx,qword ptr [rdi+8] ds:f0f0f0f0`f0f0f0f8=????????????????
```

Stack trace:
```
0:000> kvL
Child-SP          RetAddr           : Args to Child                                                           : Call Site
000000a391bf72f0 00007ffecc6b7cc3 : 0000027e42dfb8c0 000000a391bfcd40 0000027e4bd44150 000000a391bfcd40 : npdf!nitro::get_property+0x23e0
000000a391bf7340 00007ffecc71dc7d : 0000027e4bd7c500 0000027e4bd44150 0000027e4bd7c500 0000027e42dfb8c0 : npdf!CosDocClose+0x13
000000a391bf7380 00007ffecc7179a7 : 0000027e4bd44150 0000027e42de0b00 000000a391bf96b0 0000000000000007 : npdf!PDDocUpdateTextCache+0xa1d
000000a391bf73e0 00007ff6f02dd992 : 00005a568a2828eb 0000027e42de0b00 000000a391bfcd40 000000a391bf96b0 : npdf!PDDocClose+0x77
000000a391bf7440 00007ffef63c1030 : 00007ff6f02dd946 000000a391bfcd40 000000a391bfcd40 00007ffef63c336f : NitroPDF!nitro::filenames_provider::workflow::get_from_program_data+0x195b62
000000a391bf7490 00007ffef63c3298 : 00007ff6f02dd946 000000a391bf8838 0000000000000100 00007ffecc716448 : VCRUNTIME140!_CallSettingFrame+0x20
000000a391bf74c0 00007fff04ca0666 : 0000000000000000 000000a391bf96b0 0000000000000000 0000000000000000 : VCRUNTIME140!__FrameHandler3::CxxCallCatchBlock+0xe8
000000a391bf7570 0000000000000000 : 0000000000000000 0000000000000000 0000000000000000 0000000000000000 : ntdll!RcFrameConsolidation+0x6
```

The vulnerability itself lies in the function **npdf!nitro::get_property**. This function can be found with its symbols in the DLL npdf.dll. Here’s the code snippet of the get property function.
```
.text:00000001802D56A0       mov     [rsp+arg_0], rbx
.text:00000001802D56A5       mov     [rsp+arg_8], rsi
.text:00000001802D56AA       push    rdi      ; controllable                 
.text:00000001802D56AB       sub     rsp, 20h
.text:00000001802D56AF       mov     rdi, r8
.text:00000001802D56B2       mov     rsi, rdx
.text:00000001802D56B5       mov     rbx, rcx
.text:00000001802D56B8       test    r8, r8
.text:00000001802D56BB       jz      short loc_1802D571F
.text:00000001802D56BD       cmp     byte ptr [r8], 0
.text:00000001802D56C1       jz      short loc_1802D571F
.text:00000001802D56C3       mov     rcx, rdx
.text:00000001802D56C6       call    ?CosObjGetType@@YA?AW4CosType@@PEAUCosObjElementStruct@@@Z ; CosObjGetType(CosObjElementStruct *)
.text:00000001802D56CB       sub     al, 6
.text:00000001802D56CD       test    al, 0FDh
.text:00000001802D56CF       jnz     short loc_1802D571F
.text:00000001802D56D1       mov     rcx, rdi        ; Src
.text:00000001802D56D4       call    ?ASAtomFromString@@YA_KPEBD@Z ; ASAtomFromString(char const *)
.text:00000001802D56D9       mov     rdx, rax        ; unsigned __int64
.text:00000001802D56DC       mov     rcx, rsi        ; struct CosObjElementStruct *
.text:00000001802D56DF       mov     rdi, rax
.text:00000001802D56E2       call    ?CosDictKnown@@YA_NPEAUCosObjElementStruct@@_K@Z ; CosDictKnown(CosObjElementStruct *,unsigned __int64)
.text:00000001802D56E7       test    al, al
.text:00000001802D56E9       jz      short loc_1802D571F
.text:00000001802D56EB       mov     rdx, rdi        ; unsigned __int64
.text:00000001802D56EE       mov     rcx, rsi        ; struct CosObjElementStruct *
.text:00000001802D56F1       call    ?CosDictGet@@YAPEAUCosObjElementStruct@@PEAU1@_K@Z ; CosDictGet(CosObjElementStruct *,unsigned __int64)
.text:00000001802D56F6       mov     rcx, rax
.text:00000001802D56F9       mov     rdi, rax
.text:00000001802D56FC       call    ?CosObjGetType@@YA?AW4CosType@@PEAUCosObjElementStruct@@@Z ; CosObjGetType(CosObjElementStruct *)
.text:00000001802D5701       test    al, al
.text:00000001802D5703       jz      short loc_1802D571F
```
The disassembly code above indicates each CALL function to what it tries to search to fulfill its criteria when parsing for the PDF format / structure. It is basically checks for certain condition in order to meet the criteria of the PDF structure / format. Each of the API call used in the DLL can be found in Adobe PDFL SDK (available online). Here's the criteria it uses to perform a check of its structure:
```
CosObjGetType - Gets an object's type.

ASAtomFromString - methods convert between strings and ASAtom objects

CosDictGet - Gets the value of the specified key in the specified dictionary. If it is called with a stream object instead of a dictionary object, this method gets the value of the specified key from the stream's attributes dictionary.

CosDictKnown - Tests whether a specific key is found in the specified dictionary
```

An example of how the checks perform:
![Screenshot broadcast](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/3.png "Screenshot broadcast")

If none of the above conditions are met, the PDF reader will immediately close the file and prompt for an error. In this case, we modified 1-byte at the binary stream and the parser failed to handle it. We found out it lacks of checking in between object number and revision if there’s any illegal character except for value 0x20 (space). Example of binary stream:
```
<object number>(illegal character here)<object revision> obj
<<

     1                 0          obj 
<<
```

Registers with controllable RDI:
```
0:000> r
rax=000000a391bf72a0 rbx=0000027e42dfb8c0 rcx=0000027e426c8d90
rdx=0000027e426c8d90 rsi=0000027e42dfbad8 rdi=f0f0f0f0f0f0f0f0
rip=00007ffecc6b7a80 rsp=000000a391bf72f0 rbp=000000a391bfcd40
 r8=0000027e426c8d90  r9=0000027e426c8d90 r10=0000027e426c8d90
r11=0000027e426c8c68 r12=000000a391bf7520 r13=0000000000000000
r14=0000000000000000 r15=0000000000000000
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
npdf!nitro::get_property+0x23e0:
00007ffe`cc6b7a80 488b5708        mov     rdx,qword ptr [rdi+8] ds:f0f0f0f0`f0f0f0f8=????????????????
```

The Heap:
```
0:000> !heap -p -a 0000027e426c8d90 
    address 0000027e426c8d90 found in
    _HEAP @ 27e35290000
              HEAP_ENTRY Size Prev Flags            UserPtr UserSize - state
        0000027e426c8d40 000b 0000  [00]   0000027e426c8d90    00038 - (busy)
        7ffef0fb41e6 verifier!AVrfDebugPageHeapAllocate+0x0000000000000406
        7fff04d04847 ntdll!RtlDebugAllocateHeap+0x000000000000003f
        7fff04cb4a16 ntdll!RtlpAllocateHeap+0x0000000000077b26
        7fff04c3babb ntdll!RtlpAllocateHeapInternal+0x00000000000001cb
        7ffef0fd4476 verifier!AVrfpRtlAllocateHeap+0x0000000000000106
        7fff01ee2596 ucrtbase!_malloc_base+0x0000000000000036
        7ffecca34d23 npdf!nitro::notifications::notification_manager::DestroyNotification+0x0000000000297903
        7ffecc6bf4ac npdf!CosDocSetObjByID+0x000000000000668c
        7ffecc6b6d39 npdf!nitro::get_property+0x0000000000001699
        7ffecc6a6e15 npdf!PDTextIsSpaceBetween+0x000000000017f6c5
        7ffecc6b86fc npdf!CosDocOpenWithParams+0x000000000000005c
        7ffecc71c284 npdf!PDDocOpenEx+0x00000000000001d4
        7ffec3c4b247 np_stamper!CxIOFile::Write+0x0000000000016c77
        7ffec3c4f144 np_stamper!nitro::stamper::create_plugin+0x00000000000001a4
        7ff6f00e1856 NitroPDF!CxIOFile::Write+0x00000000000ef756
        7ff6f00e18f7 NitroPDF!CxIOFile::Write+0x00000000000ef7f7
        7ff6f00af76f NitroPDF!CxIOFile::Write+0x00000000000bd66f
        7ff6f00a535b NitroPDF!CxIOFile::Write+0x00000000000b325b
        7ffed7e1c684 mfc140u!AfxWinMain+0x0000000000000084
        7ff6f01976f6 NitroPDF!nitro::filenames_provider::workflow::get_from_program_data+0x000000000004f8c6
        7fff03017bd4 KERNEL32!BaseThreadInitThunk+0x0000000000000014
        7fff04c6ced1 ntdll!RtlUserThreadStart+0x0000000000000021
```

Disclosure timeline
-------------------
```
Dec 23, 2019 - Reported the security issues to Nitro Security team.
Dec 23, 2019 - Vendor acked.
Jan 8, 2020 - Follow up again with vendor. 
Jan 8, 2020 - Vendor acked with following update "the report has been acknowledged and accepted. It is now in our development lifecycle"
Feb 4, 2020 - Follow up with vendor.
Feb 4, 2020 - Vendor acked with following update "I’m happy to report that the issue has been marked as resolved, and has just completed testing. The fix will be delivered in an upcoming release of Nitro Pro 13.x"
Feb 27, 2020 - Follow up with vendor for an update (and asking if there's bounty as they mention it in their website)
Mar 3, 2020 - Vendor acked with following update "I have nominated you for a bug bounty, for the various JBIG2 reports."
Mar 3, 2020 - Received bounty from vendor with following message "“Nitro says Thank You for helping us secure our products (JBIG2) $50.00 (Amazon Gift Card)" <--- I'm not into bounty kind of stuff but What a joke LOL~
Mar 3, 2020 - Nitro released new version (13.13.2.242) https://www.gonitro.com/nps/product-details/release-notes
Mar 5, 2020 - Published writeup. Next is to request CVE as vendor don't provide any of it.
Mar 9, 2020 - [UPDATE] CVE assigned, CVE-2020-10223 and CVE-2020-10223
```
