---
layout: post
title:  "Panda Dome Antivirus - Heap-Based Buffer Overflow Vulnerability"
date:   2021-09-08 23:00:00 +0800
categories:
  - security
  - heap
  - overflow
---

Overview
-----------
Panda Security specializes in the development of endpoint security products and is part of the WatchGuard portfolio of IT security solutions. Initially focused on the development of antivirus software, the company has since expanded its line of business to advanced cyber-security services with technology for preventing cyber-crime. PANDA DOME brings together Panda's best protection, privacy and performance features into a single solution. This high-end, cross-platform antivirus product allows you to enjoy all your devices with complete peace of mind. Panda Dome’s packages also have:
- Web protection
- Performance optimization
- VPN (virtual private network)
- Parental controls
- Password manager
- Gaming mode

Panda Dome version 20.0.0.0 prone to vulnerable with heap-based buffer overflow vulnerability. An exploitable heap corruption exists in the OLE2_DeleteStreamID function of psksys.dll version 4.6.4.25 when parsing specially crafted 7zip file that leads to a heap corruption, resulting in direct code execution. This vulnerability was found via file format fuzzing. The vulnerability has been fixed by Panda Security Team with the release version 20.01.00.

Vulnerability Description
-------------------------
Specially crafted 7z files declare a specific number of substreams. However, when scanned by Panda Dome, more substreams than the declared ones are detected. This leads to a dynamic buffer overload that later causes a PSKSYS heap-based overflow when trying to free the heap that was previously corrupted. Here's how the specially crafted 7zip file looks like :) 

![grab](https://user-images.githubusercontent.com/789149/132542078-eaedc57a-8a62-44ea-8423-f1f1353288a9.png)

This vulnerability is present in the PSKSYS DLL, which is part of file format parsing. There is a vulnerability in the **OLE2_DeleteStreamID** function that used for parsing of the OLE2 stream. A specially crafted 7zip file can lead to a heap corruption and remote code execution. The vulnerability triggers even on the simplest operations performed on malformed 7z file because its related to file format parsing. Observation of stack trace:

![1](https://user-images.githubusercontent.com/789149/132537294-e10b5a22-4383-4457-a3ab-eb80d5e7dea6.png)

The initial cause was happened at the function **psksys!ANALYZER_Analyze**. The function responsible to analyze each of the files it tries to processing and parsing. Each processed file will has its own pointer. Example:

![2](https://user-images.githubusercontent.com/789149/132537424-abaa4046-2803-45aa-9c68-c08d477a7582.png)

Then it will call the other function **psksys!ANALYZER_GetConfig** to perform recognition of the file types / formats it tries to process. We can see EAX is responsible to store all of the valuable value (including pointers).

![3](https://user-images.githubusercontent.com/789149/132537514-31b53043-b180-453a-bb0d-0fde947aad49.png)

Screenshot above shows that **[ebp+10h]** pointer were stored in EAX and then it copy back to another register which is EBX. This operation is performed in the memory. The execution continue to the last path where the main root cause happened at the function **psksys!OLE2_DeleteStreamID**. This function is responsible to free the object store in the memory after parsing a file. The implementation of the stream deletion failed to free all of the object except for the EAX. This is where the heap corruption happened where it failed to free the object store in EBX. We can see this in the disassembly below:

![4](https://user-images.githubusercontent.com/789149/132537841-15b7d9ee-648a-43a1-aa3c-f3032003cf0b.png)

The heap corruption can be observed using debugger and we can see the failed freed object. If we see the stack trace below, the main root cause **psksys!OLE2_DeleteStreamID** can help us to track down the heap value. We can tell the **OLE2_DeleteStreamID** didn’t perform a proper check of the file it parse.

![6](https://user-images.githubusercontent.com/789149/132538009-d76f5b74-d578-4693-8c29-b3b79c57bbf9.png)

Free heap from previously corrupted:

![7](https://user-images.githubusercontent.com/789149/132538139-694d660c-42f7-468f-b458-576636910188.png)

This situation leads to a fully controllable heap corruption, and can be turned into remote code execution by an attacker.
```
0:075> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

KEY_VALUES_STRING: 1

    Key  : Analysis.CPU.Sec
    Value: 1

    Key  : Analysis.DebugAnalysisProvider.CPP
    Value: Create: 8007007e on DESKTOP-PIDABN7

    Key  : Analysis.DebugData
    Value: CreateObject

    Key  : Analysis.DebugModel
    Value: CreateObject

    Key  : Analysis.Elapsed.Sec
    Value: 15

    Key  : Analysis.Memory.CommitPeak.Mb
    Value: 108

    Key  : Analysis.System
    Value: CreateObject

    Key  : Timeline.OS.Boot.DeltaSec
    Value: 41291

    Key  : Timeline.Process.Start.DeltaSec
    Value: 5540

EXCEPTION_RECORD:  (.exr -1)
ExceptionAddress: 77180dec (ntdll!RtlReportCriticalFailure+0x0000004b)
   ExceptionCode: 80000003 (Break instruction exception)
  ExceptionFlags: 00000000
NumberParameters: 1
   Parameter[0]: 00000000

FAULTING_THREAD:  00001cb4

PROCESS_NAME:  PSANHost.exe

ERROR_CODE: (NTSTATUS) 0x80000003 - {EXCEPTION}  Breakpoint  A breakpoint has been reached.

EXCEPTION_CODE_STR:  80000003

EXCEPTION_PARAMETER1:  00000000

ADDITIONAL_DEBUG_TEXT:  Followup set based on attribute [Is_ChosenCrashFollowupThread] from Frame:[0] on thread:[PSEUDO_THREAD]

STACK_TEXT:  
00000000 00000000 heap_corruption!PSANHost.exe+0x0

SYMBOL_NAME:  heap_corruption!PSANHost.exe

MODULE_NAME: heap_corruption

IMAGE_NAME:  heap_corruption

STACK_COMMAND:  !heap ; ** Pseudo Context ** ManagedPseudo ** Value: e1181f0 ** ; kb

FAILURE_BUCKET_ID:  BREAKPOINT_80000003_heap_corruption!PSANHost.exe

OS_VERSION:  10.0.17763.1

BUILDLAB_STR:  rs5_release

OSPLATFORM_TYPE:  x86

OSNAME:  Windows 10

FAILURE_ID_HASH:  {839ca667-cbd7-fe00-99bf-e10ad5bb35a1}

Followup:     MachineOwner
---------
```

Disclosure timeline
-------------------
The vulnerability was reported back in December 2019. Here's the timeline of disclosure:
- December 13, 2019 - Vulnerability reported via email (with PGP) to secure@pandasecurity.com
- December 17, 2019 - Panda Security Response Team acknowledge they receive all the relevant details
- January 15, 2020 - Follow up with vendor
- January 17, 2020 - Panda Security Response Team told us they had some backlog and will get the issue reported prioritized
- January 31, 2020 - Panda Security Response Team confirmed the issue reported and told to delay disclosure
- Feb, Mar, Apr, May, Jun, Jul 2020 - Lost track LOL. I almost forgotten about this issue as well maybe due to COVID-19 Pandemic XD
- August 1, 2020 - Follow up with Panda Security
- August 4, 2020 - Panda Security Response Team told that they had fixed the vulnerability on version 20.01.00 however it gets delayed until summer hours due to some features that needs to be added. Thus, no release made during this period.
- August 11, 2020 - Panda Security Response Team rewards me with Antivirus software (latest version) with full license
- August 12, 2020 - Asking for updates on the latest version release
- Sept, Oct, Nov, Dec 2020 - Lost track again LOL
- January 2021 - Lost track againnnn
- February 9, 2021 - Asking for updates
- February 11, 2021 - Panda Security Respons Team reply saying that they had integration changes due to WatchGuard. They told that the fixed version 20.01.00 has shipped to their customers since November 2020 and informed that new version 20.02 has already released LOL~
- April 6, 2021 - Panda Security Response Team publicly disclosed security advisory and acknowledge me here [https://www.pandasecurity.com/en/support/card?id=100076](https://www.pandasecurity.com/en/support/card?id=100076)
- September 9, 2021 - Public writeup on the vulnerability reported
