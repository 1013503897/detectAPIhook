#include "detectAPIhook.h"

using namespace std;

vector<MODULE_INFO> ModuleVec;

DWORD RvaToOffset(PBYTE pPeFile, DWORD Rva)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPeFile;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pPeFile + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection =IMAGE_FIRST_SECTION(pNt);
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		if (Rva < pSection->VirtualAddress) 
		{
			return Rva;
		}
		DWORD dwAlignment = pNt->OptionalHeader.SectionAlignment;
		DWORD dwCount = pSection->Misc.VirtualSize / dwAlignment;
		dwCount += (pSection->Misc.VirtualSize % dwAlignment == 0) ? 0 : 1;
		if (Rva >= pSection->VirtualAddress && Rva < pSection->VirtualAddress + dwCount * dwAlignment)
		{
			return Rva - pSection->VirtualAddress + pSection->PointerToRawData;
		}
		pSection++;
	}
	return 0;
}

void mytoupper(char* str) 
{
	for (int i = 0; i < strlen(str); i++) 
	{
		if (str[i] >= 'a' && str[i] <= 'z') 
		{
			str[i] = toupper(str[i]);
		}
	}
}

DWORD GetProcAddressByFile(LPCSTR lpDllName, LPCSTR lpProcName, HANDLE hProcess, DWORD& FOAFunction)
{
	DWORD hModule = NULL;
	DWORD hDllFile = NULL;
	for (int i = 0; i < ModuleVec.size(); i++)
	{
		mytoupper(ModuleVec[i].FileFullPath);
		mytoupper((char*)lpDllName);
		if (strstr(ModuleVec[i].FileFullPath, (char*)lpDllName))
		{
			hModule = ModuleVec[i].ImageBase;
			hDllFile = (DWORD)LoadLibraryA(ModuleVec[i].FileFullPath);
			break;
		}
	}
	if (!hDllFile)
	{
		hDllFile = (DWORD)LoadLibraryA(lpDllName);
	}
	if (!hModule)
	{
		hModule = hDllFile;
	}
	PIMAGE_DOS_HEADER pDestanceDos = (PIMAGE_DOS_HEADER)hDllFile;
	PIMAGE_NT_HEADERS pDestanceNt = (PIMAGE_NT_HEADERS)(hDllFile + pDestanceDos->e_lfanew);
	PIMAGE_DATA_DIRECTORY pExportDir = &(pDestanceNt->OptionalHeader.DataDirectory[0]);
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pExportDir->VirtualAddress + hDllFile);
	PINT pFunction = (PINT)(pExport->AddressOfFunctions + hDllFile);
	PINT pFunctionName = (PINT)(pExport->AddressOfNames + hDllFile);
	PWORD pFunctionOrdin = (PWORD)(pExport->AddressOfNameOrdinals + hDllFile);
	WORD Order = 0;
	if (((DWORD)lpProcName & 0xFFFF0000) == 0)
	{
		Order = (DWORD)lpProcName - pExport->Base;
		FOAFunction = (DWORD)pFunction[Order] + hDllFile;
		return (DWORD)hModule + pFunction[Order];
	}
	else
	{
		for (int i = 0; i < pExport->NumberOfNames; i++)
		{
			char* pFunname2 = (char*)(pFunctionName[i]) + hDllFile;
			if (!strcmp(pFunname2, lpProcName))
			{
				Order = i;
				break;
			}
		}
	}
	FOAFunction = (DWORD)pFunction[pFunctionOrdin[Order]] + (DWORD)hDllFile;
	return (DWORD)hModule + pFunction[pFunctionOrdin[Order]];
}

bool isforwardstring(char* str)
{
	if (strlen(str) >= 99 || strlen(str) <= 3)
		return false;
	for (int i = 0; i < strlen(str); i++)
	{
		if ((str[i] >= 'A' && str[i] <= 'Z') || (str[i] >= 'a' && str[i] <= 'z') ||
			str[i] == '-' || str[i] == '_' || str[i] == '.' || (str[i] >= '0' && str[i] <= '9'))
			continue;
		else
		{
			return false;
		}
	}
	return true;
}

void CheckIAT(DWORD dwProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	GetRemoteModuleInfo(dwProcessID);
	HMODULE hModule = GetRemoteImageBase(dwProcessID);
	PBYTE pModuleBuf = NULL;
	DWORD dwReadModuleSize = 0;
	pModuleBuf = new BYTE[sizeof(IMAGE_DOS_HEADER)];
	ReadProcessMemory(hProcess, hModule, pModuleBuf, sizeof(IMAGE_DOS_HEADER), &dwReadModuleSize);
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBuf;
	DWORD dwNewFile = pDos->e_lfanew;
	delete[]pModuleBuf;
	DWORD dwHeaderSize = dwNewFile + sizeof(IMAGE_NT_HEADERS);
	pModuleBuf = new BYTE[dwHeaderSize];
	ReadProcessMemory(hProcess, hModule, pModuleBuf, dwHeaderSize, &dwReadModuleSize);
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pModuleBuf + dwNewFile);
	PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNt->OptionalHeader;
	PIMAGE_DATA_DIRECTORY pImportDir = pOptionalHeader->DataDirectory + 1;
	DWORD dwImportVA = (DWORD)((DWORD)hModule + pImportDir->VirtualAddress);
	DWORD dwSize = pImportDir->Size;
	delete[]pModuleBuf;
	PBYTE pImportBuf = new BYTE[dwSize];
	ReadProcessMemory(hProcess, (LPVOID)dwImportVA, pImportBuf, dwSize, &dwReadModuleSize);
	PIMAGE_IMPORT_DESCRIPTOR pImport = PIMAGE_IMPORT_DESCRIPTOR(pImportBuf);
	while (pImport->Name != 0)
	{
		DWORD pIatRVA = (DWORD)(pImport->FirstThunk + (DWORD)hModule);
		DWORD pIntRVA = (DWORD)(pImport->OriginalFirstThunk + (DWORD)hModule);
		PIMAGE_THUNK_DATA pIat = (PIMAGE_THUNK_DATA)new BYTE[0x1000];
		PIMAGE_THUNK_DATA pInt = (PIMAGE_THUNK_DATA)new BYTE[0x1000];
		ReadProcessMemory(hProcess, (LPVOID)pIatRVA, pIat, 0x1000, &dwReadModuleSize);
		ReadProcessMemory(hProcess, (LPVOID)pIntRVA, pInt, 0x1000, &dwReadModuleSize);
		char* pDllnameVA = (char*)((DWORD)hModule + pImport->Name);
		char* pDllname = new char[MAX_PATH];
		ReadProcessMemory(hProcess, (LPVOID)pDllnameVA, pDllname, MAX_PATH, &dwReadModuleSize);

		while (pIat->u1.AddressOfData != 0)
		{
			DWORD RemoteFunVA = 0;
			DWORD LocalFunVA = 0;
			char* pFunnameVA;
			char* pFunname;
			if (IMAGE_SNAP_BY_ORDINAL32(pInt->u1.AddressOfData) != 1)
			{
				pFunnameVA = (char*)(pInt->u1.ForwarderString + (DWORD)hModule);
				pFunname = new char[MAX_PATH];
				ReadProcessMemory(hProcess, (LPVOID)pFunnameVA, pFunname, MAX_PATH, &dwReadModuleSize);
				RemoteFunVA = GetProcAddressByFile(pDllname, PIMAGE_IMPORT_BY_NAME(pFunname)->Name, hProcess, LocalFunVA);
				delete[] pFunname;
			}
			else
			{
				DWORD Ordinal = pInt->u1.Ordinal & 0x0000FFFF;
				RemoteFunVA = GetProcAddressByFile(pDllname, (LPCSTR)Ordinal, hProcess, LocalFunVA);
			}
			if (RemoteFunVA != pIat->u1.Function)
			{
				char pTempDll[100] = { 0 };
				char pTempFuction[100] = { 0 };
				while (isforwardstring((char*)LocalFunVA))
				{
					strcpy(pTempDll, (char*)LocalFunVA);
					char* p = strchr(pTempDll, '.');
					*p = 0;
					strcpy(pTempFuction, p + 1);
					strcat(pTempDll, ".dll");
					RemoteFunVA = GetProcAddressByFile(pTempDll, pTempFuction, hProcess, LocalFunVA);
				}
				if (RemoteFunVA != pIat->u1.Function)
				{
					pFunnameVA = (char*)(pInt->u1.AddressOfData + (DWORD)hModule);
					pFunname = new char[MAX_PATH];
					ReadProcessMemory(hProcess, (LPVOID)pFunnameVA, pFunname, MAX_PATH, &dwReadModuleSize);
					printf("%s!%s Is Hooked\r\n", pDllname, PIMAGE_IMPORT_BY_NAME(pFunname)->Name);
					delete[] pFunname;
				}
			}
			pInt++;
			pIat++;
		}
		pImport++;
	}
	delete[] pImportBuf;
	printf("CheckIAT() Over\r\n");
}

void CheckEAT(DWORD dwProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	GetRemoteModuleInfo(dwProcessID);
	for (auto it : ModuleVec)
	{
		HMODULE hModule = (HMODULE)it.ImageBase;
		PBYTE pModuleBuf = NULL;
		DWORD dwReadModuleSize = 0;
		pModuleBuf = new BYTE[sizeof(IMAGE_DOS_HEADER)];
		ReadProcessMemory(hProcess, hModule, pModuleBuf, sizeof(IMAGE_DOS_HEADER), &dwReadModuleSize);
		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pModuleBuf;
		DWORD dwNewFile = pDos->e_lfanew;
		delete[] pModuleBuf;
		DWORD dwHeaderSize = dwNewFile + sizeof(IMAGE_NT_HEADERS);
		pModuleBuf = new BYTE[dwHeaderSize];
		ReadProcessMemory(hProcess, hModule, pModuleBuf, dwHeaderSize, &dwReadModuleSize);
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pModuleBuf + dwNewFile);
		PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = &pNt->OptionalHeader;
		PIMAGE_DATA_DIRECTORY pExportDir = pOptionalHeader->DataDirectory;
		if (!pExportDir->Size|| !pExportDir->VirtualAddress)
		{
			continue;
		}
		PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)new BYTE[pExportDir->Size];
		ReadProcessMemory(hProcess, (LPVOID)((DWORD)hModule + pExportDir->VirtualAddress), pExport, pExportDir->Size, NULL);
		DWORD* pFunctions = new DWORD[pExport->NumberOfFunctions];
		ReadProcessMemory(hProcess, (LPVOID)((DWORD)hModule + pExport->AddressOfFunctions), pFunctions, sizeof(DWORD) * pExport->NumberOfFunctions, NULL);
		DWORD* pNames = new DWORD[pExport->NumberOfNames];
		ReadProcessMemory(hProcess, (LPVOID)((DWORD)hModule + pExport->AddressOfNames), pNames, sizeof(DWORD) * pExport->NumberOfNames, NULL);
		WORD* pOridianl = new WORD[pExport->NumberOfNames];
		ReadProcessMemory(hProcess, (LPVOID)((DWORD)hModule + pExport->AddressOfNameOrdinals), pOridianl, sizeof(WORD) * pExport->NumberOfNames, NULL);
		WORD Order = 0;
		for (int i = 0; i < pExport->NumberOfNames; i++)
		{
			char* pFunnameVA = (char*)(pNames[i] + (DWORD)hModule);
			char* pFunname = new char[MAX_PATH];
			DWORD FOAFunction;
			ReadProcessMemory(hProcess, (LPVOID)pFunnameVA, pFunname, MAX_PATH, &dwReadModuleSize);
			DWORD FuntionVA = GetProcAddressByFile(it.FileFullPath, pFunname, hProcess, FOAFunction);
			if (FuntionVA != (DWORD)hModule + pFunctions[pOridianl[i]])
			{
				printf("%s Is Hooked\r\n", pFunname);
			}
			delete[] pFunname;
		}
	}
	printf("CheckEAT() Over\r\n");
}

HMODULE GetRemoteImageBase(DWORD dwProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	DWORD dwNeed1 = 0;
	DWORD dwNeed2 = 0;
	EnumProcessModulesEx(hProcess, NULL, 0, &dwNeed1, LIST_MODULES_ALL);
	HMODULE* pModule = new HMODULE[dwNeed1];
	EnumProcessModulesEx(hProcess, pModule, dwNeed1, &dwNeed2, LIST_MODULES_ALL);
	return *pModule;
}

VOID GetRemoteModuleInfo(DWORD dwProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;
	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID);
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32))
	{
		CloseHandle(hModuleSnap);
		return;
	}
	ModuleVec.clear();
	do
	{
		MODULE_INFO ModuleInfo{};
		strcpy(ModuleInfo.FileFullPath, me32.szExePath);
		ModuleInfo.ImageBase = (DWORD)me32.modBaseAddr;
		ModuleVec.push_back(ModuleInfo);
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
}

int _tmain(int argc, _TCHAR* argv[])
{
	CheckIAT(20188);// hardcode pid :(
	CheckEAT(20188);
	system("pause");
	return 0;
}
