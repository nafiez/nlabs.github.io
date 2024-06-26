---
layout: post
title:  "CVE-2018-1000097 - Sharutils (unshar) - Buffer Overflow"
date:   2018-09-19 18:34:10 +0700
tags:
    - CVE-2018-1000097
---

Description
-----------
Sharutils is a package for creating and manipulating shell archives that can be readily emailed. A shell archive is a file that can 
be processed by a Bourne-type shell to unpack the original collection of files. Shar makes so-called shell archives out of many 
files, preparing them for transmission by electronic mail services (converting binary data to ASCII representations, breaking the 
text into multiple shar scripts, etc.). Unshar is the safe way to extract and reassemble the original files. It will automatically 
strip off the mail headers and other introductory text.

Vulnerability Description
-------------------------
Sharutils sharutils (unshar command) version 4.15.2 contains a Buffer Overflow vulnerability in Affected component on the 
file unshar.c at line 75, function looks_like_c_code. Failure to perform checking of the buffer containing input line that can 
result in Could lead to code execution. This attack appear to be exploitable via Victim have to run unshar command on a specially 
crafted file.

Sharutils (unshar) Fuzzing 
--------------------------
We fuzzed the sharutils package (unshar) with AFL and came up with quite number of results. Compile the program with the following 
command
  ```$ CC=afl-gcc CXX=afl-g++ AFL_USE_ASAN=1 ./configure```

Once it passed, then run following command
  ```$ AFL_USE_ASAN=1 make```
  
This will compile the binary with ASAN and AFL. Once configure properly, we run the AFL fuzzer with the following 
command **afl-fuzz -m none -i input/ -o output/ – ./unshar @@**. Within 4 hours, we managed to get 5 unique crashed. We then verified 
if the crashed are indeed valid. 
```
john@fuzzing:~/sharutils-4.15.2/src$ ./unshar output/crashes/id:000000,sig:06,src:000052,op:havoc,rep:64
===================================================================20801==
ERROR: AddressSanitizer: heap-buffer-overflow on address 0xb6101100 at pc 0x0804c6e3 bp 0xbfcb9138 sp 0xbfcb9128
READ of size 1 at 0xb6101100 thread T0
    #0 0x804c6e2 in looks_like_c_code /home/john/sharutils-4.15.2/src/unshar.c:81
    #1 0x804c6e2 in find_archive /home/john/sharutils-4.15.2/src/unshar.c:253
    #2 0x804c6e2 in unshar_file /home/john/sharutils-4.15.2/src/unshar.c:379
    #3 0x804a2f4 in validate_fname /home/john/sharutils-4.15.2/src/unshar-opts.c:604
    #4 0x804a2f4 in main /home/john/sharutils-4.15.2/src/unshar-opts.c:639
    #5 0xb787d636 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18636)
    #6 0x804ab95  (/home/john/sharutils-4.15.2/src/unshar+0x804ab95)

0xb6101100 is located 0 bytes to the right of 4096-byte region [0xb6100100,0xb6101100)
allocated by thread T0 here:#0 0xb7ab1dee in malloc (/usr/lib/i386-linux-gnu/libasan.so.2+0x96dee)
    #1 0x804c9e4 in init_unshar /home/john/sharutils-4.15.2/src/unshar.c:450#2 0xb787d636 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18636)

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/john/sharutils-4.15.2/src/unshar.c:81 looks_like_c_code
Shadow bytes around the buggy address:
  0x36c201d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x36c201e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x36c201f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x36c20200: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x36c20210: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x36c20220:[fa]fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36c20230: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36c20240: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36c20250: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36c20260: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x36c20270: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):Addressable:           00
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
==20801==ABORTING
```

Vulnerability Analysis
----------------------
Our observation found that it was from **unshar.c** and the root cause started on **find_archive()**. In the line 449, we can see **rw_buffer** has allocated **rw_base_size** which is 8192 bytes. 

```
Line 449 - 450:
rw_base_size = GET_PAGE_SIZE;
rw_buffer    = malloc (rw_base_size);
```
At line 45, you can see the GET_PAGE_SIZE buffer size has been set to 8192 bytes. 
```
Line 45:
# define GET_PAGE_SIZE  8192
```
We observed the size of BUFSIZ was allocated to 8192 bytes, however in this case the rw_base_size size is not similar with the memory page allocation. Thus, the issue allow to write out of the allocated memory for rw_buffer. Failure to do so, can lead to application crash. 
```
Line 243 - 249:
if (!fgets (rw_buffer, BUFSIZ, file))     // BUFSIZ is not equal to rw_buffer (allocated buffer) that leads to overflow
{
    if (!start)
        error (0, 0, _("Found no shell commands in %s"), name);
    return false;
}
```

Patch
-----
We reported the security issue via proper channel by sending an email to security@gnu.org and to Bugtraq mailing-list. Initially, we find out Red Hat / Fedora Security team taking care of the issue, https://bugzilla.redhat.com/show_bug.cgi?id=1548018 and ship the fixed to stable repository on 2018-03-06. It then follow by Ubuntu security and published advisory https://usn.ubuntu.com/3605-1/ on 2018-03-22. 

Patch Diff
----------
```
diff -Nru sharutils-4.15.2/debian/changelog sharutils-4.15.2/debian/changelog
--- sharutils-4.15.2/debian/changelog	2015-08-03 15:31:35.000000000 +0000+++ sharutils-4.15.2/debian/changelog	2018-03-21 23:30:23.000000000 +0000@@ -1,3 +1,12 @@+sharutils (1:4.15.2-1ubuntu0.1) xenial-security; urgency=medium
++  * SECURITY UPDATE: Buffer overflow
+    - debian/patches/CVE-2018-1000097.patch: fix in
+      src/unshar.c.
+    - CVE-2018-1000097++ -- Leonidas S. Barbosa <leo.barbosa@canonical.com>  Wed, 21 Mar 2018 20:30:03 -0300+
 sharutils (1:4.15.2-1) unstable; urgency=medium
 
   * New upstream release.
diff -Nru sharutils-4.15.2/debian/control sharutils-4.15.2/debian/control
--- sharutils-4.15.2/debian/control	2015-05-31 23:39:08.000000000 +0000+++ sharutils-4.15.2/debian/control	2018-03-21 23:30:26.000000000 +0000@@ -1,7 +1,8 @@Source: sharutils
 Section: utils
 Priority: optional
-Maintainer: Santiago Vila <sanvila@debian.org>+Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>+XSBC-Original-Maintainer: Santiago Vila <sanvila@debian.org>
 Standards-Version: 3.9.6
 Build-Depends: debhelper (>= 9.20120311), texinfo
 Homepage: http://www.gnu.org/software/sharutils/
diff -Nru sharutils-4.15.2/debian/patches/CVE-2018-1000097.patch sharutils-4.15.2/debian/patches/CVE-2018-1000097.patch
--- sharutils-4.15.2/debian/patches/CVE-2018-1000097.patch	1970-01-01 00:00:00.000000000 +0000+++ sharutils-4.15.2/debian/patches/CVE-2018-1000097.patch	2018-03-21 23:29:56.000000000 +0000@@ -0,0 +1,59 @@+Backported of:++The bellow patch should fix it. I don't know if sharutils author prefers
+reading up to a memory page size or an I/O buffer size.
+++>From 1067cdba6d08f2a765cb0ea371189a5b703eb4db Mon Sep 17 00:00:00 2001+From: =?UTF-8?q?Petr=20P=C3=ADsa=C5=99?= <address@hidden>+Date: Thu, 22 Feb 2018 16:39:43 +0100+Subject: [PATCH] Fix a heap-buffer-overflow in find_archive()
+MIME-Version: 1.0+Content-Type: text/plain; charset=UTF-8+Content-Transfer-Encoding: 8bit
++rw_buffer has allocated rw_base_size bytes. But subsequend fgets() in
+find_archive() reads up-to BUFSIZ bytes.
++On my system, BUFSIZ is 8192. rw_base_size is usually equaled to
+a memory page size, 4096 on my system. Thus find_archive() can write
+beyonded allocated memmory for rw_buffer array:++$ valgrind -- ./unshar 
+/tmp/id\:000000\,sig\:06\,src\:000005+000030\,op\:splice\,rep\:4+==30582== Memcheck, a memory error detector
+==30582== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
+==30582== Using Valgrind-3.13.0 and LibVEX; rerun with -h for copyright info
+==30582== Command: ./unshar 
+/tmp/id:000000,sig:06,src:000005+000030,op:splice,rep:4+==30582==+==30582== Invalid write of size 1+==30582==    at 0x4EAB480: _IO_getline_info (in /usr/lib64/libc-2.27.so)
+==30582==    by 0x4EB47C2: fgets_unlocked (in /usr/lib64/libc-2.27.so)
+==30582==    by 0x10BF60: fgets_unlocked (stdio2.h:320)
+==30582==    by 0x10BF60: find_archive (unshar.c:243)
+==30582==    by 0x10BF60: unshar_file (unshar.c:379)
+==30582==    by 0x10BCCC: validate_fname (unshar-opts.c:604)
+==30582==    by 0x10BCCC: main (unshar-opts.c:639)
+==30582==  Address 0x523a790 is 0 bytes after a block of size 4,096 alloc'd
+==30582==    at 0x4C2DBBB: malloc (vg_replace_malloc.c:299)
+==30582==    by 0x10C670: init_unshar (unshar.c:450)
+==30582==    by 0x10BC55: main (unshar-opts.c:630)
++This was reported in
+<http://lists.gnu.org/archive/html/bug-gnu-utils/2018-02/msg00004.html>.++Signed-off-by: Petr PÃ­saÅ™ <address@hidden>+diff --git a/src/unshar.c b/src/unshar.c
+index 80bc3a9..0fc3773 100644+--- a/src/unshar.c
++++ b/src/unshar.c
+@@ -240,7 +240,7 @@ find_archive (char const * name, FILE * file, off_t start)
+       off_t position = ftello (file);
+ 
+       /* Read next line, fail if no more and no previous process.  */+-      if (!fgets (rw_buffer, BUFSIZ, file))
++      if (!fgets (rw_buffer, rw_base_size, file))
+ 	{
+ 	  if (!start)
+ 	    error (0, 0, _("Found no shell commands in %s"), name);
diff -Nru sharutils-4.15.2/debian/patches/series sharutils-4.15.2/debian/patches/series
--- sharutils-4.15.2/debian/patches/series	2015-05-11 16:41:13.000000000 +0000+++ sharutils-4.15.2/debian/patches/series	2018-03-21 23:29:56.000000000 +0000@@ -1 +1,2 @@99-config-guess-config-sub
+CVE-2018-1000097.patch
```
