#@author mooncat-greenpy
#@category KinGAidra
#@keybinding 
#@menupath 
#@toolbar 


import kingaidra


def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(kingaidra.ai.task.KinGAidraChatTaskService)

    convo = service.get_task(state.getEnvironmentVar("KEY"))

    msg = convo.get_msg(convo.get_msgs_len() - 1)

    type = service.get_task_type(state.getEnvironmentVar("KEY"))
    if type == kingaidra.ai.task.TaskType.CHAT and "test" in msg:
        data = """Hello! How can I assist you today?"""
    elif type == kingaidra.ai.task.TaskType.CHAT and "Please explain what the following decompiled C function does." in msg and "FUN_01222300" in msg:
        data = """Let's break down the decompiled C function step-by-step. The function's purpose seems to be related to interacting with system processes, specifically locating a process (likely `Explorer.exe`), opening it, and then obtaining a process token.

### Function Signature:
```cpp
void __fastcall FUN_01222300(PHANDLE param_1)
```
- This function takes one argument, `param_1`, which is a pointer to a `HANDLE` (likely a process token, based on its usage).

### Variables:
```cpp
HANDLE hObject;
int iVar1;
HANDLE ProcessHandle;
undefined4 local_234;
undefined local_230[4];
DWORD local_22c;
ushort local_210[260];
uint local_8;
```
- **`hObject`**: A handle to the snapshot of system processes.
- **`iVar1`**: Used as a return value indicator for system calls.
- **`ProcessHandle`**: A handle to a process that will be opened later.
- **`local_234`**: Likely used as a structure to hold data returned from process queries.
- **`local_230[4]`**: Unused or temporarily stored data.
- **`local_22c`**: Holds the process ID of a found process (likely `Explorer.exe`).
- **`local_210[260]`**: A buffer to store information about the process being inspected.
- **`local_8`**: Appears to store a XOR'd value for some kind of stack protection or context.

### Code Breakdown:

#### Step 1: Initialize some variables
```cpp
local_8 = DAT_01253004 ^ (uint)&stack0xfffffffc;
_memset(local_230,0,0x228);
```
- The `local_8` variable seems to be initialized with an XOR operation, possibly related to stack protection or some security measure.
- `local_230` is zeroed out with `_memset` to ensure there is no uninitialized data. It has a size of 0x228 bytes (568 bytes).

#### Step 2: Create a snapshot of system processes
```cpp
hObject = (HANDLE)CreateToolhelp32Snapshot(2,0);
```
- The `CreateToolhelp32Snapshot` function creates a snapshot of the system's processes. The argument `2` specifies that the snapshot should contain information about processes. The `0` argument specifies no specific flags.
- If the snapshot cannot be created, it will return `0xFFFFFFFF`, which is checked in the next conditional.

#### Step 3: Handle failure to create snapshot
```cpp
if (hObject == (HANDLE)0xffffffff) {
    FUN_01230cbe(local_8 ^ (uint)&stack0xfffffffc);
    return;
}
```
- If the snapshot creation fails (`hObject == 0xFFFFFFFF`), the function calls another function `FUN_01230cbe`, passing the XOR'd value of `local_8`, and then returns early.

#### Step 4: Initialize process enumeration
```cpp
local_234 = 0x22c;
iVar1 = Process32FirstW(hObject, &local_234);
```
- The `local_234` variable is set to `0x22C`, and then the function `Process32FirstW` is called to enumerate the first process in the snapshot. This function will return `0` if no processes are found, or non-zero if a process is found.

#### Step 5: Iterate over processes
```cpp
while (true) {
    if (iVar1 == 0) {
        CloseHandle(hObject);
        FUN_01230cbe(local_8 ^ (uint)&stack0xfffffffc);
        return;
    }
```
- The `while (true)` loop continues indefinitely until a process is found or we decide to break out.
- If `iVar1 == 0` (i.e., no processes were found), the function will close the snapshot handle (`CloseHandle(hObject)`), call `FUN_01230cbe` again, and return.

#### Step 6: Look for "Explorer.exe"
```cpp
    iVar1 = FUN_01239c4a(local_210, (ushort *)L"Explorer.exe");
    if (iVar1 == 0) break;
```
- The function `FUN_01239c4a` appears to compare the current process in `local_210` to the name `"Explorer.exe"`.
- If it finds a match, it breaks out of the loop (`iVar1 == 0` would indicate success).

#### Step 7: Continue iterating if process is not "Explorer.exe"
```cpp
    iVar1 = Process32NextW(hObject, &local_234);
}
```
- If the current process isn't `"Explorer.exe"`, the function continues to the next process in the snapshot with `Process32NextW`.

#### Step 8: Open the process and get its token
```cpp
ProcessHandle = OpenProcess(0x400, 0, local_22c);
OpenProcessToken(ProcessHandle, 0xf01ff, param_1);
CloseHandle(ProcessHandle);
```
- Once `"Explorer.exe"` is found, the process ID (`local_22c`) is used to open the process using `OpenProcess`. The `0x400` flag indicates that the process is opened with `PROCESS_QUERY_INFORMATION` rights.
- The `OpenProcessToken` function is then called to get the token for the process (with `0xf01ff` specifying the token rights).
- The token handle is stored in `param_1`, which was passed as a parameter to the function.

#### Step 9: Clean up
```cpp
CloseHandle(hObject);
FUN_01230cbe(local_8 ^ (uint)&stack0xfffffffc);
return;
```
- Finally, the snapshot handle (`hObject`) is closed, and the function `FUN_01230cbe` is called again with the XOR'd value of `local_8` (perhaps for cleanup or security), and the function returns.

### Summary:
1. The function creates a snapshot of all system processes.
2. It iterates through the processes to find `Explorer.exe`.
3. Once it finds `Explorer.exe`, it opens the process and retrieves its access token.
4. The token is stored in the `param_1` pointer, which was passed to the function.
5. It performs cleanup by closing handles and calling another function `FUN_01230cbe`.

### Expected Behavior:
When executed, the function will:
- Locate `Explorer.exe` in the system process list.
- Open the process with specific query rights.
- Retrieve and store the process's access token in the provided `param_1`.
- Clean up all resources and exit.

This function might be part of a larger program that interacts with system processes, possibly for managing or impersonating the `Explorer.exe` process."""
    elif type == kingaidra.ai.task.TaskType.CHAT and "Decompile the following assembly code into equivalent C code." in msg and "FUN_01222300" in msg:
        data = """The assembly code provided is quite complex and involves calls to Windows API functions such as `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`, `OpenProcess`, `OpenProcessToken`, and `CloseHandle`. These are used to interact with system processes, and the logic appears to involve creating a snapshot of running processes, filtering them, and checking for certain processes (like `Explorer.exe`). The program then interacts with processes by opening their tokens and performing various actions.

### Let's decompile the assembly to C code step by step:

```c
#include <windows.h>
#include <tlhelp32.h>
#include <advapi32.h>

void FUN_01222300(void) {
    // Local variables
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    BOOL processFound = FALSE;

    // Initialize process entry structure
    memset(&pe32, 0, sizeof(PROCESSENTRY32));

    // Take a snapshot of all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    // Initialize PROCESSENTRY32 structure
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Start enumerating processes
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Check for "Explorer.exe"
            if (_stricmp(pe32.szExeFile, "Explorer.exe") == 0) {
                // Process found, now open the process
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess != NULL) {
                    // Open process token
                    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                        // Successfully opened token, perform some operations
                        // (Additional logic goes here, depending on what needs to be done with the token)
                        processFound = TRUE;
                    }
                    // Close process handle
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe32) && !processFound);
    }

    // Close the snapshot handle
    CloseHandle(hSnapshot);

    // If no process was found, do additional actions
    if (!processFound) {
        // (Additional logic can go here)
    }
}
```

### Explanation of the C Code:
1. **Snapshot Creation**: The assembly code creates a snapshot of the current running processes with `CreateToolhelp32Snapshot`. In C, we do this with the `CreateToolhelp32Snapshot` function, using `TH32CS_SNAPPROCESS` to indicate that we are interested in processes.
   
2. **Process Enumeration**: The assembly code uses `Process32First` and `Process32Next` to iterate over the processes. The C code uses the same API calls to check each process. It looks for `Explorer.exe`, which is a common process in Windows.

3. **Checking the Process**: When a match is found (the process is `Explorer.exe`), the code opens the process with `OpenProcess`. It uses `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ` as the desired access rights.

4. **Token Operations**: If `Explorer.exe` is found, the program attempts to open the process's access token with `OpenProcessToken`. The C code doesn't specify what happens with the token, but in the original assembly, it seems like further operations might be intended on the token (this could include security operations like altering access rights or querying the token).

5. **Handling the Snapshot and Closing Handles**: After processing, it is important to close the snapshot and any opened handles to avoid resource leaks, as done with `CloseHandle` in both the C code and assembly.

### Notes:
- **The assembly logic includes some additional operations that aren't fully translated here**, particularly with handling tokens and process-related actions. These actions would need more context to be properly converted into C code.
- **Error handling** is minimal in the assembly code, which means some areas in the C code (like checking `INVALID_HANDLE_VALUE` for `CreateToolhelp32Snapshot` or `NULL` for `OpenProcess`) help prevent runtime errors.
- **The `FUN_01230cbe` and other function calls** in the original assembly are not fully clear, so they aren't included in the C code. These would need to be examined separately to understand their purpose.

"""
    elif type == kingaidra.ai.task.TaskType.DECOM_REFACTOR_FUNC_PARAM_VAR and "FUN_01222300" in msg:
        data = """```json
{
    "new_func_name": "retrieve_process_token",
    "orig_func_name": "FUN_01222300",
    "parameters": [
        {
            "new_param_name": "processTokenHandle",
            "orig_param_name": "param_1"
        }
    ],
    "variables": [
        {
            "new_var_name": "snapshotHandle",
            "orig_var_name": "hObject"
        },
        {
            "new_var_name": "processEntry",
            "orig_var_name": "local_234"
        },
        {
            "new_var_name": "processHandle",
            "orig_var_name": "ProcessHandle"
        },
        {
            "new_var_name": "currentProcessID",
            "orig_var_name": "local_22c"
        },
        {
            "new_var_name": "processNameBuffer",
            "orig_var_name": "local_210"
        },
        {
            "new_var_name": "initialStackValue",
            "orig_var_name": "local_8"
        }
    ]
}
```"""
    elif type == kingaidra.ai.task.TaskType.DECOM_REFACTOR_DATATYPE and "FUN_01222300" in msg:
        data = """To address the data type issues in the provided code, I will analyze the function and suggest corrections for each variable type where necessary. Based on common knowledge of Windows API programming and typical C code structures, I will correct the data types where appropriate.

### Review of Key Variables:
1. `hObject` is assigned the result of `CreateToolhelp32Snapshot`, which returns a `HANDLE`.
2. `ProcessHandle` is assigned the result of `OpenProcess`, which also returns a `HANDLE`.
3. `local_234` is passed to `Process32FirstW` and `Process32NextW`, which expect a `PROCESSENTRY32W` structure, but `undefined4` is used here, which is incorrect.
4. `local_230` is used as a buffer with the size `0x228`, which seems to be a byte array (likely `unsigned char[]`).
5. `local_22c` is used in `OpenProcess`, which seems to be a `DWORD` (a 32-bit unsigned integer).
6. `local_210` is used as a buffer for `Process32FirstW` and `Process32NextW`, which likely deals with a wide-character string or array.

### Correcting the Data Types:

- `local_234` should be of type `PROCESSENTRY32W` instead of `undefined4`.
- `local_230` should be an array of `unsigned char` (byte buffer).
- `local_22c` should be of type `DWORD` (since it's used in a WinAPI function call).
- `local_210` should be an array of `wchar_t` (wide character string).

### The Updated Data Types in JSON Format:

```json
[
    {
        "new_datatype": "PROCESSENTRY32W",
        "orig_datatype": "undefined4",
        "var_name": "local_234"
    },
    {
        "new_datatype": "DWORD[4]",
        "orig_datatype": "undefined",
        "var_name": "local_230"
    },
    {
        "new_datatype": "DWORD",
        "orig_datatype": "undefined",
        "var_name": "local_22c"
    },
    {
        "new_datatype": "WCHAR[260]",
        "orig_datatype": "ushort[260]",
        "var_name": "local_210"
    }
]
```

### Explanation of Changes:
1. **local_234**: This variable is passed into functions like `Process32FirstW` and `Process32NextW`, which require a `PROCESSENTRY32W` structure. `undefined4` is an incorrect type here, so it should be `PROCESSENTRY32W`.
2. **local_230**: Since it is initialized as a buffer using `_memset`, this is likely intended to be a byte buffer (array of `unsigned char`).
3. **local_22c**: This is used in the `OpenProcess` call, which expects a `DWORD` as one of its arguments. Therefore, the type should be `DWORD`.
4. **local_210**: It is used with `Process32FirstW` and `Process32NextW`, which expect a `wchar_t` (wide character type) string for process names. Thus, `local_210` should be of type `wchar_t[260]` instead of `ushort[260]`."""
    elif type == kingaidra.ai.task.TaskType.RESOLVE_DATATYPE and "PROCESSENTRY32W" in msg:
        data = """Sure! Below is the `PROCESSENTRY32W` structure in C for a 32-bit system, written without using `typedef`, `#include`, or `#define`. This includes all the dependent data types and structures:

```c
struct PROCESSENTRY32W {
    unsigned long dwSize;                  // The size of the structure, in bytes
    unsigned long cntUsage;                // The usage count of the process
    unsigned long th32ProcessID;           // The process ID of the process
    unsigned long th32DefaultHeapID;       // The default heap ID of the process
    unsigned long th32ModuleID;            // The module ID
    unsigned long cntThreads;              // The number of threads in the process
    unsigned long th32ParentProcessID;     // The parent process ID
    long pcPriClassBase;                   // The base priority of the process
    unsigned long dwFlags;                 // The flags of the process
    unsigned short szExeFile[260];         // The full path to the executable file
};
```

### Explanation of the Fields:
1. **dwSize**: This specifies the size of the structure, which is required by `Process32First` and `Process32Next` to know the size of the data they are working with. You should set this to the size of `PROCESSENTRY32W` before calling these functions.
   
2. **cntUsage**: The number of times the process has been referenced by other processes.

3. **th32ProcessID**: The process ID of the process.

4. **th32DefaultHeapID**: The ID of the default heap for the process.

5. **th32ModuleID**: The ID of the module.

6. **cntThreads**: The number of threads in the process.

7. **th32ParentProcessID**: The process ID of the parent process.

8. **pcPriClassBase**: The base priority class of the process.

9. **dwFlags**: Various flags related to the process.

10. **szExeFile**: A wide-character array holding the full path of the executable file associated with the process. The length of the array (260) is large enough to accommodate the maximum path length (commonly 260 characters in Windows).

This structure corresponds to the 32-bit version, and the use of wide-character strings (`szExeFile`) suggests the use of Unicode. The `PROCESSENTRY32W` structure is used in the Windows API to retrieve information about a process in the system, typically via `CreateToolhelp32Snapshot`, `Process32First`, and `Process32Next`."""
    elif type == kingaidra.ai.task.TaskType.KEY_FUNC and "Given a list of strings found within a malware sample" in msg:
        data = """Here are the strings from the list that could potentially be useful for further analysis:

### 1. **URLs or IP addresses**
- `CONNECT %s:%d HTTP/1.1 \r\nUser-Agent: Mozilla/v5.0\r\nHost: %s:%d\r\nProxy-Connection: Keep-Alive\r\nPragma: no-cache\r\nContent-Length: 0\r\n\r\n`
- `Proxy-Authenticate`
- `Proxy-Connection`
- `ProxyUser`
- `ProxyPW`
- `Proxy-Connection`

These strings suggest communication with a remote server or C2 (Command-and-Control) infrastructure, possibly via HTTP or through a proxy, indicating potential network activity associated with the malware.

### 2. **File paths or registry keys**
- `Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap`
- `SYSTEM\\CurrentControlSet\\Control\\ProductOptions`
- `HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%x`
- `SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\`

These registry keys indicate potential persistence mechanisms and system configuration information, which could be useful in tracking how the malware interacts with the system or establishes persistence.

### 3. **Function names or API calls**
- `CreateThread`
- `CreateProcessW`
- `GetModuleHandleA`
- `LoadLibraryA`
- `FindFirstFileW`
- `CreateFileW`
- `GetProcAddress`
- `WriteFile`
- `DeleteFileW`
- `Sleep`
- `TerminateThread`
- `VirtualAlloc`
- `VirtualFree`
- `CryptAcquireContextW`
- `CryptCreateHash`
- `RegOpenKeyA`
- `InternetQueryOptionW`

These are indicative of various common actions such as thread creation, file system access, process manipulation, and cryptographic operations. Some suggest actions that may be used for file manipulation or evading detection.

### 4. **Encryption keys or sensitive data**
- `Proxy-Authorization: Basic %s`
- `CryptAcquireContextW`
- `CryptCreateHash`
- `CryptHashData`
- `CryptReleaseContext`

The presence of cryptographic functions suggests the possibility of encrypted communication or payloads. The `Basic` authorization method also hints at potential hardcoded credentials used for remote communication.

### 5. **Error messages or logs**
- `"Error2:\r\nOpen [%s] error! %d"`
- `"Error2:\r\nCan't find [%s]!Check the file name and try again!"`
- `"Error2:\r\nCreateThread DownloadFile[%s] Error!"`
- `"Error2:\r\nUploadFile [%s] Error:Connect Server Failed!"`
- `"Error2:\r\nThe Size of [%s] is zero!"`
- `"Error2:\r\nCreateThread UploadFile[%s] Error!"`

These error strings may indicate how the malware handles issues related to file downloading, uploading, and thread creation, potentially helping in the identification of failure points or abnormal behaviors.

### 6. **Hardcoded credentials or authentication tokens**
- `ProxyUser`
- `ProxyPW`
- `Proxy-Authenticate`
- `Proxy-Authorization: Basic %s`

These are potentially hardcoded credentials used for authentication when communicating with a remote server, which could provide insight into how the malware authenticates to its C2 server.

### 7. **Strings associated with known malware families or threat actor tactics**
- `BMSDLIGRADAF`

This string could be associated with a known malware family or an identifier that can link the sample to previous campaigns or actor groups, making it relevant for attribution or identifying shared techniques.

By focusing on these strings, you can gather valuable information regarding the malware's functionality, persistence, and communication methods, as well as any cryptographic or authentication mechanisms it might use."""
    else:
        data = ""

    service.commit_task(state.getEnvironmentVar("KEY"), data)

if __name__ == "__main__":
    main()
