/*CreateFileA, HeapAlloc, OpenProcessToken, OpenProcess, VirtualAlloc, GetProcAddress, LoadRemoteLibraryR/LoadLibrary, HeapFree, CloseHandle*/
#include <windows.h>
#include <stdio.h>


int main(void){

    DWORD pid;
    printf("target PID: ");
    scanf("%d", &pid);

    HANDLE hFile = CreateFileW(L"malicious dll path", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        printf("[-] failed to open file, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] dll has been opened\n");


    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("[-] OpenProcess failed, error: [%d]\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
        printf("[+] process [%d] has been opened\n", pid);

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        printf("[-] OpenProcessToken failed, error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

        HANDLE Hheep = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, sizeof(hFile));
        if(Hheep == NULL){
            printf("[-] faile to create heap [%d]\n", GetLastError());
            CloseHandle(hFile);
            return 1;
        }
        printf("[+] heap has been create at address: [%p]\n", Hheep);

        PVOID Halloc = HeapAlloc(Hheep, 0, sizeof(hFile));
        if(Halloc == NULL){
            printf("[-] faile to allocate heap [%d]\n", GetLastError());
            CloseHandle(hFile);
            return 1;
        }
        printf("[+] heap has been allocated into address: [%p]\n", Halloc);

        CloseHandle(hProcess);
        CloseHandle(hFile);
        CloseHandle(Hheep);
        CloseHandle(hToken);
return 0;
}
