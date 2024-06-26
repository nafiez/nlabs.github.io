---
layout: post
title:  "CVE-2018-10717 - MiniUPnP ngiflib 0.4 - Buffer Overflow"
date:   2018-09-19 03:43:45 +0700
tags:
    - CVE-2018-10717
---

Description
-----------
The DecodeGifImg function in ngiflib.c in MiniUPnP ngiflib 0.4 does not consider the bounds of the pixels data structure, which allows 
remote attackers to cause a denial of service (WritePixels heap-based buffer overflow and application crash) or possibly have 
unspecified other impact via a crafted GIF file, a different vulnerability than CVE-2018-10677.

Vulnerability Analysis
----------------------
There’s an buffer overflow found in ngiflib.c line 206. Size of **tocopy** exceeded the **pixels** size, and when copying 
into **context->frbuff_p.p8** it overflow here. 
```
static void WritePixels(struct ngiflib_img * i, struct ngiflib_decode_context * context, const u8 * pixels, u16 n) {
	u16 tocopy;	
	struct ngiflib_gif * p = i->parent;

	while(n > 0) {
		tocopy = (context->Xtogo < n) ? context->Xtogo : n;
		if(!i->gce.transparent_flag) {
#ifndef NGIFLIB_INDEXED_ONLY
			if(p->mode & NGIFLIB_MODE_INDEXED) {
#endif /* NGIFLIB_INDEXED_ONLY */
				ngiflib_memcpy(context->frbuff_p.p8, pixels, tocopy);   **// crash happened here**
				pixels += tocopy;
```

Address-Sanitizer Output
------------------------
```
==3568==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x63000000fe00 at pc 0x7fc5dfe17904 bp 0x7ffd40601780 sp 0x7ffd40600f28
WRITE of size 1 at 0x63000000fe00 thread T0
    #0 0x7fc5dfe17903 in __asan_memcpy (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x8c903)
    #1 0x40bb4b in memcpy /usr/include/x86_64-linux-gnu/bits/string3.h:53
    #2 0x40bb4b in WritePixels /home/john/ngiflib/ngif/ngiflib.c:206
    #3 0x40bb4b in DecodeGifImg /home/john/ngiflib/ngif/ngiflib.c:548
    #4 0x411cc3 in LoadGif /home/john/ngiflib/ngif/ngiflib.c:784
    #5 0x404d5f in SDL_LoadAnimatedGif /home/john/ngiflib/ngif/ngiflibSDL.c:136
    #6 0x401fa7 in main /home/john/ngiflib/ngif/SDLaffgif.c:107
    #7 0x7fc5df74882f in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2082f)
    #8 0x403118 in _start (/home/john/ngiflib/ngif/SDLaffgif+0x403118)

0x63000000fe00 is located 0 bytes to the right of 64000-byte region [0x630000000400,0x63000000fe00)
allocated by thread T0 here:
    #0 0x7fc5dfe23602 in malloc (/usr/lib/x86_64-linux-gnu/libasan.so.2+0x98602)
    #1 0x41390b in LoadGif /home/john/ngiflib/ngif/ngiflib.c:607

SUMMARY: AddressSanitizer: heap-buffer-overflow ??:0 __asan_memcpy
Shadow bytes around the buggy address:
  0x0c607fff9f70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c607fff9f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c607fff9f90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c607fff9fa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c607fff9fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c607fff9fc0:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c607fff9fd0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c607fff9fe0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c607fff9ff0: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c607fffa000: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c607fffa010: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Heap right redzone:      fb
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack partial redzone:   f4
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
==3568==ABORTING
```

Patch
-----
https://github.com/miniupnp/ngiflib/commit/cf429e0a2fe26b5f01ce0c8e9b79432e94509b6e

References
----------
https://github.com/miniupnp/ngiflib/issues/3
https://nvd.nist.gov/vuln/detail/CVE-2018-10717
https://exchange.xforce.ibmcloud.com/vulnerabilities/142847
