#include <stdio.h>
#include <Windows.h>

#define Error(name, err) printf("[!] %s failed with code: %d, 0x%x\n", name, err, err)
#define NT_FUNC_SIZE 21 // NT Functions Size (Bytes)

int main(int argc, char** argv) {

	if (argc != 2) {
		printf("[!] Usage: %s <DLL path>\n", argv[0]);
		return -1;
	}

	LPCSTR DllName = argv[1];

	HMODULE hDll = GetModuleHandleA(DllName);
	if (!hDll) {
		HMODULE hDll = LoadLibraryA(DllName);
		if (!hDll) {
			Error("LoadLibraryA", GetLastError());
			goto CleanUp;
		}
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hDll;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((UINT64)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((UINT64)hDll + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hDll + pExport->AddressOfFunctions);
	DWORD* pAddressOfNames = (DWORD*)((BYTE*)hDll + pExport->AddressOfNames);
	WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hDll + pExport->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
		char* functionName = (char*)((BYTE*)hDll + pAddressOfNames[i]);
		PVOID funcAddr = (PVOID)((BYTE*)hDll + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
		
		/*if (
			strncmp(functionName, "Nt", 2) == 0 ||
			strncmp(functionName, "Zw", 2) == 0 ||
			strncmp(functionName, "Rtl", 3) == 0
		) {
			printf("[+] %s: \n\n", functionName);*/

		if (*(BYTE*)((UINT64)funcAddr) == 0xe9) {
			printf("[+] \"jmp\" found in: %s -> ", functionName);
			for (int i = 0; i < NT_FUNC_SIZE; i++)
				printf("%02x ", *(BYTE*)((UINT64)funcAddr + i));

			printf("\n");
		}
	}

CleanUp:
	if (hDll)
		CloseHandle(hDll);

	getchar();
	return 0;
}