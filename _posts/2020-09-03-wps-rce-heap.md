---
layout: post
title:  "CVE-2020-25291 - Kingsoft WPS Office Remote Heap Corruption Vulnerability"
date:   2020-09-03 21:45:00 +0800
tags:
    - CVE-2020-25291
---

Overview
--------
WPS Office is an office suite for Microsoft Windows, macOS, Linux, iOS and Android, developed by Zhuhai-based Chinese software developer Kingsoft. WPS Office is made up of three primary components: WPS Writer, WPS Presentation, and WPS Spreadsheet. The personal basic version is free to use. A remote code execution vulnerability exists in WPS Office software that is caused when the Office software improperly handles objects in memory while parsing specially crafted Office files. An attacker who successfully exploited the vulnerability could run arbitrary code in the context of the current user. Failure could lead to denial-of-service. Vulnerable product WPS Office affecting version 11.2.0.9453.

Vulnerability Analysis
----------------------
Heap corruption found in Qt module used in WPS Office for image format parsing. A specially crafted image file embedded in WPS office could trigger the vulnerability. When open the specially crafted document file, an access violation triggered. EDX pointer to array and EAX is an index to array.
```
0:000> g
(c50.b4): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
eax=000000c0 ebx=006f1c48 ecx=cd2aefbc edx=cd2c6f80 esi=2ed7ae18 edi=0000001c
eip=6ba13321 esp=006f1b44 ebp=006f1b44 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00210202
QtCore4!QMatrix::dy+0x48a8:
6ba13321 8b448210        mov     eax,dword ptr [edx+eax*4+10h] ds:002b:cd2c7290=????????
```

How does the crash trigger? Let’s take a look into PNG header format. 
```
00029E30  FF 89 50 4E 47 0D 0A 1A 0A 00 00 00 0D 49 48 44  ÿ‰PNG........IHD
00029E40  52 00 00 02 80 00 00 01 C6 04 03 00 00 00 16 0A  R...€...Æ.......
00029E50  27 FC 00 00 00 04 67 41 4D 41 00 00 B1 88 95 98  'ü....gAMA..±ˆ•˜
00029E60  F4 A6 00 00 00 30 50 4C 54 45 00 00 00 80 00 00  ô¦...0PLTE...€..
00029E70  00 80 00 80 80 00 00 00 80 80 00 80 00 80 80 80  .€.€€...€€.€.€€€
00029E80  80 80 C0 C0 C0 FF 00 00 00 FF 00 FF FF 00 00 00  €€ÀÀÀÿ...ÿ.ÿÿ...
00029E90  FF FF 00 FF 00 FF FF FF FF FF 7B 1F B1 C4 00 00  ÿÿ.ÿ.ÿÿÿÿÿ{.±Ä..
```

Starting at the offset 0x29E31 - 0x29E34 is a signature header for PNG file format. The structure of PNG header file:
```
PNG signature --> IHDR --> gAMA --> PLTE --> pHYs --> IDAT --> IEND
```

In this context, the vulnerability lies on an embedded PNG file in a word document when QtCore library used in WPS Office Suite are parsing a PLTE structure and trigger a heap corruption. At the offset 0x29E82 until 0x29E85 is where the parsing of the palette failed and thus triggers a memory corruption in the heap. Stack trace before crash trigger:
```
00 00ee1790 6b8143ef QtCore4!path_gradient_span_gen::path_gradient_span_gen+0x6a71
01 00ee17f0 6b814259 QtCore4!QBrush::setMatrix+0x234
02 00ee58d4 6b8249a4 QtCore4!QBrush::setMatrix+0x9e
03 00ee58ec 6b80cc84 QtCore4!QImage::rect+0x22b
04 00ee5908 6b857ccc QtCore4!QTransform::inverted+0xec8
05 00ee629c 6b81c55b QtCore4!QSvgFillStyle::setFillOpacity+0x1b59
06 00ee6480 6b896844 QtCore4!QPainter::drawPixmap+0x1c98
07 00ee6574 6d1e0fbd QtCore4!QPainter::drawImage+0x325
08 00ee6594 6d0dd155 kso!GdiDrawHoriLineIAlt+0x11a1a
```

Before QtCore4 takes place to parse embedded image, we could see the last call from KSO module trying to process an image kso!GdiDrawHoriLineIAlt. Analyzing the function where the exception occurs using IDA Pro to disassemble the application. The last crash path as in following (WinDBG result):
```
QtCore4!QMatrix::dy+0x48a8:
6ba13321 8b448210        mov     eax,dword ptr [edx+eax*4+10h] ds:002b:cd2c7290=????????
```

When open in IDA Pro, we could disassemble the function as in following:
```
.text:67353315                 push    ebp
.text:67353316                 mov     ebp, esp
.text:67353318                 movzx   eax, byte ptr [ecx+edx]  ; crash here
.text:6735331C                 mov     ecx, [ebp+arg_0]
.text:6735331F                 mov     edx, [ecx]
.text:67353321                 mov     eax, [edx+eax*4+10h]
.text:67353325                 mov     ecx, eax
```

Using the information from our crash dump we know that the application triggers an access violation at 0x67353321 (mov  eax, [edx+eax*4+10h]). We can see EAX register are controlled with 0xc0 value. So, from here we can make a few assumptions on the state of the registers at instructions leading up to our exception.  What’s important to note, is that prior to our exception, we can see that the value contained in ECX (0xc0) is being written to an arbitrary location as defined by the following instruction:
```
mov     ecx, [ebp+arg_0]
```

Furthermore, we note that beyond our faulting instruction the offset of EBP stored at an ECX register. We set a breakpoint at the instruction (with offset 0x6ba1331c) mentioned earlier to observe the memory. Once our breakpoint trigger, we can see the first value c45adfbc is referencing to another pointer, which supposed to be pointer to an array.
```
Breakpoint 0 hit
eax=0000000f ebx=004f1b40 ecx=d3544100 edx=0000001c esi=d1200e18 edi=0000001c
eip=6ba1331c esp=004f1a34 ebp=004f1a34 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00200202
QtCore4!QMatrix::dy+0x48a3:
6ba1331c 8b4d08          mov     ecx,dword ptr [ebp+8] ss:002b:004f1a3c=c45adfbc

0:000> dc ebp+8
004f1a3c  c45adfbc 00000048 00000000 6f13830f  ..Z.H..........o
004f1a4c  004f5cc8 00000000 00000000 00000000  .\O.............
004f1a5c  00000000 004f65a0 004f662c 00000000  .....eO.,fO.....
004f1a6c  779eae8e 00000000 00000001 3f800000  ...w...........?
004f1a7c  3f800000 3f31e4f8 3f800000 3f800000  ...?..1?...?...?
004f1a8c  3f800000 3f31e4f8 3f800000 3de38800  ...?..1?...?...=
004f1a9c  3de38800 3d9e1c8a 3c834080 004f3c00  ...=...=.@.<.<O.
004f1aac  4101c71c 6ba13315 3f800000 4081c71c  ...A.3.k...?...@
```

Observing the memory reference from c45adfbc found another pointer. The first value ab69cf80 is always represented as pointer to anywhere it references to. The pointer ab69cf80 is basically index array of our pointer.
```
0:000> dc c45adfbc
c45adfbc  ab69cf80 d3544100 00000003 00000280  ..i..AT.........
c45adfcc  0000055a 00000012 c0c0c0c0 1c3870e2  Z............p8.
c45adfdc  40ad870e 1c3870e2 40ad870e 00000000  ...@.p8....@....
c45adfec  00000000 c0c0c0c1 6c1d12c0 00000000  ...........l....
c45adffc  c0c0c0c0 ???????? ???????? ????????  ....????????????
c45ae00c  ???????? ???????? ???????? ????????  ????????????????
c45ae01c  ???????? ???????? ???????? ????????  ????????????????
c45ae02c  ???????? ???????? ???????? ????????  ????????????????

0:000> dc ab69cf80
ab69cf80  00000001 0000001c 00000010 00000001  ................ // 0000001c is overwritten in the register EDX and EDI before we trigger crash
ab69cf90  ff000000 ff800000 ff008000 ff808000  ................ 
ab69cfa0  ff000080 ff800080 ff008080 ff808080  ................
ab69cfb0  ffc0c0c0 ffff0000 ff00ff00 ffffff00  ................ // ffc0c0c0 where it will be stored in EAX after crash, at the moment it only takes 0xf value in EAX
ab69cfc0  ff0000ff ffff00ff ff00ffff ffffffff  ................
ab69cfd0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
ab69cfe0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
ab69cff0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
```

Since we know the path that it will land the crash, we could simply set a breakpoint with the following command below. The command will get the pointer value of "edx+eax*4+10" and check if it meets 0xc0.
```
bp 6ba13321 ".if (poi(edx+eax*4+10) == 0xc0) {} .else {gc}"

0:000> g
eax=000000c0 ebx=004f1b40 ecx=c45adfbc edx=ab69cf80 esi=d1200e18 edi=0000001c
eip=6ba13321 esp=004f1a34 ebp=004f1a34 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00200202
QtCore4!QMatrix::dy+0x48a8:
6ba13321 8b448210        mov     eax,dword ptr [edx+eax*4+10h] ds:002b:ab69d290=????????
```

If we observe the stack, we can see the following execution:
```
004f1a38 6ba3cb98 QtCore4!path_gradient_span_gen::path_gradient_span_gen+0x6a74
004f1a3c c45adfbc 
004f1a40 00000048 
004f1a44 00000000 
004f1a48 6f13830f verifier!DphCommitMemoryForPageHeap+0x16f
004f1a4c 004f5cc8 
004f1a50 00000000 
004f1a54 00000000 
004f1a58 00000000 
004f1a5c 00000000 
004f1a60 004f65a0 
004f1a64 004f662c 
004f1a68 00000000 
004f1a6c 779eae8e ntdll!RtlAllocateHeap+0x3e
```

If we disassemble 6ba3cb98, we can see the following disassembly code. The actual root cause is on this code.
```
6ba3cb89 8b96b4000000    mov     edx,dword ptr [esi+0B4h]
6ba3cb8f 8b4df4          mov     ecx,dword ptr [ebp-0Ch]
6ba3cb92 52              push    edx
6ba3cb93 8bd7            mov     edx,edi
6ba3cb95 ff5580          call    dword ptr [ebp-80h]
6ba3cb98 8b4e7c          mov     ecx,dword ptr [esi+7Ch]


C pseudo code

grad = *(&ptr_grad);
if ( grad > 0.0099999998 )
{
   input_value = grad_size(check, size, input);
   ptr_grad = *(input);
   ... cut here ...
```

We set the breakpoint on the 6ba3cb89 address and observing the ESI+0xB4 and we can see a pointer that referencing to another place:
```
0:000> r
eax=00000000 ebx=00791878 ecx=00000005 edx=00793938 esi=cb07de18 edi=0000001c
eip=6ba3cb89 esp=00791780 ebp=00791870 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00200202
QtCore4!path_gradient_span_gen::path_gradient_span_gen+0x6a65:
6ba3cb89 8b96b4000000    mov     edx,dword ptr [esi+0B4h] ds:002b:cb07decc=cf69afbc

0:000> dc esi+0B4h
cb07decc  cf69afbc c0c0c000 00000000 00000100  ..i.............
cb07dedc  c0c0c0c0 00000000 00000000 00000000  ................
cb07deec  00000000 00000000 00000000 00000000  ................
cb07defc  00000000 cf030fd0 00000000 00000000  ................
cb07df0c  00000000 00000000 00000000 00000000  ................
cb07df1c  c0c0c0c0 00000000 3ff00000 00000000  ...........?....
cb07df2c  00000000 00000000 00000000 00000000  ................
cb07df3c  00000000 00000000 3ff00000 00000000  ...........?....

0:000> dc cf69afbc
cf69afbc  c88baf80 d1326100 00000003 00000280  .....a2.........
cf69afcc  0000055f 00000012 c0c0c0c0 1c3870e2  _............p8.
cf69afdc  40ad870e 1c3870e2 40ad870e 00000000  ...@.p8....@....
cf69afec  00000000 c0c0c0c1 6c1d12c0 00000000  ...........l....
cf69affc  c0c0c0c0 ???????? ???????? ????????  ....????????????
cf69b00c  ???????? ???????? ???????? ????????  ????????????????
cf69b01c  ???????? ???????? ???????? ????????  ????????????????
cf69b02c  ???????? ???????? ???????? ????????  ????????????????

0:000> dc c88baf80
c88baf80  00000001 0000001c 00000010 00000001  ................
c88baf90  ff000000 ff800000 ff008000 ff808000  ................
c88bafa0  ff000080 ff800080 ff008080 ff808080  ................
c88bafb0  ffc0c0c0 ffff0000 ff00ff00 ffffff00  ................
c88bafc0  ff0000ff ffff00ff ff00ffff ffffffff  ................
c88bafd0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
c88bafe0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
c88baff0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
```
From here we can tell the code didn't actually free anything from the pointer. Once it moves to EDX, EDX will then hold the pointer to the index array:
```
eax=00000000 ebx=00791878 ecx=00000005 edx=cf69afbc esi=cb07de18 edi=0000001c
eip=6ba3cb8f esp=00791780 ebp=00791870 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00200202
QtCore4!path_gradient_span_gen::path_gradient_span_gen+0x6a6b:
6ba3cb8f 8b4df4          mov     ecx,dword ptr [ebp-0Ch] ss:002b:00791864=d1326100

0:000> dc cf69afbc
cf69afbc  c88baf80 d1326100 00000003 00000280  .....a2.........
cf69afcc  0000055f 00000012 c0c0c0c0 1c3870e2  _............p8.
cf69afdc  40ad870e 1c3870e2 40ad870e 00000000  ...@.p8....@....
cf69afec  00000000 c0c0c0c1 6c1d12c0 00000000  ...........l....
cf69affc  c0c0c0c0 ???????? ???????? ????????  ....????????????
cf69b00c  ???????? ???????? ???????? ????????  ????????????????
cf69b01c  ???????? ???????? ???????? ????????  ????????????????
cf69b02c  ???????? ???????? ???????? ????????  ????????????????

0:000> dc c88baf80
c88baf80  00000001 0000001c 00000010 00000001  ................
c88baf90  ff000000 ff800000 ff008000 ff808000  ................
c88bafa0  ff000080 ff800080 ff008080 ff808080  ................
c88bafb0  ffc0c0c0 ffff0000 ff00ff00 ffffff00  ................
c88bafc0  ff0000ff ffff00ff ff00ffff ffffffff  ................
c88bafd0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
c88bafe0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
c88baff0  c0c0c0c0 c0c0c0c0 c0c0c0c0 c0c0c0c0  ................
```

Stack trace after crash:
```
0:000> kvL
 # ChildEBP RetAddr  Args to Child              
00 012f18d4 6ba3cb98 cc53afbc 00000048 00000000 QtCore4!QMatrix::dy+0x48a8
01 012f19d0 6b8143ef 00000000 012f1b78 012f1a5c QtCore4!path_gradient_span_gen::path_gradient_span_gen+0x6a74
02 012f1a30 6b814259 0000002e 012f5bd0 00000000 QtCore4!QBrush::setMatrix+0x234
03 012f5b14 6b8249a4 0000003b 012f5b68 cc780e18 QtCore4!QBrush::setMatrix+0x9e
04 012f5b2c 6b80cc84 0000003b 012f5b68 cc780e18 QtCore4!QImage::rect+0x22b
05 012f5b48 6b857ccc 0000003b 012f5b68 cc780e18 QtCore4!QTransform::inverted+0xec8
06 012f64dc 6b81c55b 00000000 003c0000 00000000 QtCore4!QSvgFillStyle::setFillOpacity+0x1b59
07 012f66c0 6b896844 012f6724 cc818ff0 0000001c QtCore4!QPainter::drawPixmap+0x1c98
08 012f67b4 6d1e0fbd 012f69ec 012f66d4 012f6864 QtCore4!QPainter::drawImage+0x325
09 012f67d4 6d0dd155 012f6a54 012f69ec 012f6864 kso!GdiDrawHoriLineIAlt+0x11a1a
0a 012f67ec 6d0c8d88 012f69ec 012f68e0 012f6864 kso!kpt::PainterExt::drawBitmap+0x23
```

Heap analysis:
```
0:000> !heap -p -a cc53afbc
    address cc53afbc found in
    _DPH_HEAP_ROOT @ 6731000
    in busy allocation (  DPH_HEAP_BLOCK:         UserAddr         UserSize -         VirtAddr         VirtSize)
                                cc36323c:         cc53afa8               58 -         cc53a000             2000
    6f13ab70 verifier!AVrfDebugPageHeapAllocate+0x00000240
    77a9909b ntdll!RtlDebugAllocateHeap+0x00000039
    779ebbad ntdll!RtlpAllocateHeap+0x000000ed
    779eb0cf ntdll!RtlpAllocateHeapInternal+0x0000022f
    779eae8e ntdll!RtlAllocateHeap+0x0000003e
    6f080269 MSVCR100!malloc+0x0000004b
    6f08233b MSVCR100!operator new+0x0000001f
    6b726c67 QtCore4!QImageData::create+0x000000fa
    6b726b54 QtCore4!QImage::QImage+0x0000004e
    6b7a0e21 QtCore4!png_get_text+0x00000436
    6b79d7a8 QtCore4!QImageIOHandler::setFormat+0x000000de
    6b79d457 QtCore4!QPixmapData::fromFile+0x000002bf
    6b725eb4 QtCore4!QImageReader::read+0x000001e2
    6d0ca585 kso!kpt::VariantImage::forceUpdateCacheImage+0x0000254e
    6d0c5964 kso!kpt::Direct2DPaintEngineHelper::operator=+0x00000693
    6d0c70d0 kso!kpt::RelativeRect::unclipped+0x00001146
    6d0c8d0c kso!kpt::VariantImage::forceUpdateCacheImage+0x00000cd5
    6d451d5c kso!BlipCacheMgr::BrushCache+0x0000049a
    6d451e85 kso!BlipCacheMgr::GenerateBitmap+0x0000001d
    6d453227 kso!BlipCacheMgr::GenCachedBitmap+0x00000083
    6d29bb92 kso!drawing::PictureRenderLayer::render+0x000009b6
    6d450fb1 kso!drawing::RenderTargetImpl::paint+0x00000090
    6d29b528 kso!drawing::PictureRenderLayer::render+0x0000034c
    6d2a2d83 kso!drawing::VisualRenderer::render+0x00000060
    6d2b8970 kso!drawing::SingleVisualRenderer::drawNormal+0x000002b5
    6d2b86a7 kso!drawing::SingleVisualRenderer::draw+0x000001e1
    6d2b945e kso!drawing::SingleVisualRenderer::draw+0x00000046
    6d3d0142 kso!drawing::ShapeVisual::paintEvent+0x0000044a
    680a2b5c wpsmain!WpsShapeTreeVisual::getHittestSubVisuals+0x000068f1
    6d0e36df kso!AbstractVisual::visualEvent+0x00000051
    6d3cbe97 kso!drawing::ShapeVisual::visualEvent+0x0000018f
    6d0eba90 kso!VisualPaintEvent::arriveVisual+0x0000004e

0:000> dt _DPH_BLOCK_INFORMATION cc780e18-0x20
verifier!_DPH_BLOCK_INFORMATION
   +0x000 StartStamp       : 0xc0c0c0c0
   +0x004 Heap             : 0xc0c0c0c0 Void
   +0x008 RequestedSize    : 0xc0c0c0c0
   +0x00c ActualSize       : 0xc0c0c0c0
   +0x010 Internal         : _DPH_BLOCK_INTERNAL_INFORMATION
   +0x018 StackTrace       : 0xc0c0c0c0 Void
   +0x01c EndStamp         : 0xc0c0c0c0
```

The last heap entry in a segment is usually a free block. The status of the heap blocks indicates as free blocks. The heap block states that the size of the previous block is 00108 and the size of the current block is 00a30. The prior block is reporting its own size to be 0x20 bytes, which does not match up. Usage of the heap block at location 05f61000 seems to be the possibility that the usage of that heap block caused the metadata of the following block to become corrupt. Heap block:
```
0:000> !heap -a 05f60000 
Index   Address  Name      Debugging options enabled
  1:   05f60000 
    Segment at 05f60000 to 0605f000 (00001000 bytes committed)
    Flags:                00000002
    ForceFlags:           00000000
    Granularity:          8 bytes
    Segment Reserve:      00100000
    Segment Commit:       00002000
    DeCommit Block Thres: 00000200
    DeCommit Total Thres: 00002000
    Total Free Size:      00000146
    Max. Allocation Size: fffdefff
    Lock Variable at:     05f60258
    Next TagIndex:        0000
    Maximum TagIndex:     0000
    Tag Entries:          00000000
    PsuedoTag Entries:    00000000
    Virtual Alloc List:   05f6009c
    Uncommitted ranges:   05f6008c
            05f61000: 000fe000  (1040384 bytes)
    FreeList[ 00 ] at 05f600c0: 05f605b8 . 05f605b8  
        05f605b0: 00108 . 00a30 [100] - free

    Segment00 at 05f60000:
        Flags:           00000000
        Base:            05f60000
        First Entry:     05f604a8
        Last Entry:      0605f000
        Total Pages:     000000ff
        Total UnCommit:  000000fe
        Largest UnCommit:00000000
        UnCommitted Ranges: (1)

    Heap entries for Segment00 in Heap 05f60000
         address: psize . size  flags   state (requested size)
        05f60000: 00000 . 004a8 [101] - busy (4a7)
        05f604a8: 004a8 . 00108 [101] - busy (107) Internal 
        05f605b0: 00108 . 00a30 [100]
        05f60fe0: 00a30 . 00020 [111] - busy (1d)
        05f61000:      000fe000      - uncommitted bytes.

0:000> dd 05f60fe0
05f60fe0  a9b3c836 03007087 05f6008c 05f6008c
05f60ff0  05f60038 05f60038 05f61000 000fe000
05f61000  ???????? ???????? ???????? ????????
05f61010  ???????? ???????? ???????? ????????
05f61020  ???????? ???????? ???????? ????????
05f61030  ???????? ???????? ???????? ????????
05f61040  ???????? ???????? ???????? ????????
05f61050  ???????? ???????? ???????? ????????
```

Disclosure timeline
-------------------
The vulnerability was reported in August 2020. Timeline of disclosure:

- 2020-08-04 - Sent email to various mailing list (sales and support) of WPS that publicly available. 
- 2020-08-10 - WPS team responding that the report can be forwarded to them.
- 2020-08-11 - Asking for further info such as advisory and disclosing to appropriate channel, etc. 
- 2020-08-17 - Follow up with WPS team on previous request.
- 2020-08-18 - WPS team respond they will take care of it and forward to dev team.
- 2020-08-18 - Technical report and Proof-of-Concept provided via email (without encryption).
- 2020-08-25 - Follow up with WPS on progress of the report.
- 2020-08-26 - WPS updates saying that the issue has been forwarded to dev team. 
- 2020-08-28 - WPS sent an email saying that the issue has been fixed in the latest download version, 11.2.0.9403. 
- 2020-08-28 - Tested the new version against the provided PoC and confirm the issue has been fixed.
- 2020-08-28 - Asking for advisory or change log of the updates from WPS team.
- 2020-09-03 - Writeup of the vulnerability. Request CVE.
- 2020-09-14 - CVE assigned, CVE-2020-25291.
- 2020-09-15 - WPS Security team approached saying that the advisory of their program is exists and has written the advisory here, https://security.wps.cn/notices/6
