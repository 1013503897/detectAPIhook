#include "windows.h"
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

using namespace std;

typedef struct _MODULE_INFO
{
    char FileFullPath[MAX_PATH];
    DWORD ImageBase;
}MODULE_INFO, * PMODULE_INFO;

vector<MODULE_INFO> ModuleVec;

DWORD RvaToOffset(PBYTE pPeFile, DWORD Rva)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPeFile;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pPeFile + pDos->e_lfanew);

    PIMAGE_SECTION_HEADER pSection =
        IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
    {
        if (Rva < pSection->VirtualAddress) {
            return Rva;
        }
        DWORD dwAlignment =
            pNt->OptionalHeader.SectionAlignment;
        DWORD dwCount = pSection->Misc.VirtualSize / dwAlignment;
        dwCount += (pSection->Misc.VirtualSize % dwAlignment == 0) ? 0 : 1;
        if (Rva >= pSection->VirtualAddress &&
            Rva < pSection->VirtualAddress + dwCount * dwAlignment)
        {
            return Rva - pSection->VirtualAddress +
                pSection->PointerToRawData;
        }
        pSection++;
    }
    return 0;
}

char* mytoupper(char* s) {
    int len = strlen(s);
    for (int i = 0; i < len; i++) {
        if (s[i] >= 'a' && s[i] <= 'z') {
            s[i] = toupper(s[i]);
        }
    }
    return s;
}

DWORD GetProcAddressByFile(LPCSTR lpDllName, LPCSTR lpProcName, HANDLE hProcess, DWORD& FOAFunction)
{
    DWORD hModule = NULL;
    DWORD hDllFile = NULL;
    for (int i = 0; i < ModuleVec.size(); i++)
    {
        if (strstr(mytoupper(ModuleVec[i].FileFullPath), mytoupper((char*)lpDllName)))
        {
            hModule = ModuleVec[i].ImageBase;
            hDllFile = (DWORD)LoadLibraryA(ModuleVec[i].FileFullPath);
            break;
        }
    }
    if (hDllFile == NULL)
    {
        hDllFile = (DWORD)LoadLibraryA(lpDllName);
    }
    if (hModule == 0)
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

void CheckIAT(DWORD ProcessID)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID);
    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &me32))
    {
        printf("Module32First");
        CloseHandle(hModuleSnap);
        return;
    }

    do
    {
        MODULE_INFO ModuleInfo{};
        strcpy(ModuleInfo.FileFullPath, me32.szExePath);
        ModuleInfo.ImageBase = (DWORD)me32.modBaseAddr;
        ModuleVec.push_back(ModuleInfo);
    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    DWORD dwNeed1 = 0;
    DWORD dwNeed2 = 0;
    EnumProcessModulesEx(hProcess, NULL, 0, &dwNeed1, LIST_MODULES_ALL);
    HMODULE* pModule = new HMODULE[dwNeed1];
    EnumProcessModulesEx(hProcess, pModule, dwNeed1, &dwNeed2, LIST_MODULES_ALL);
    HMODULE hModule = *pModule;
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
            DWORD FunVA;
            DWORD FunRVA = 0;
            char* pFunnameVA;
            char* pFunname;
            if (IMAGE_SNAP_BY_ORDINAL32(pInt->u1.AddressOfData) != 1)
            {
                pFunnameVA = (char*)(pInt->u1.ForwarderString + (DWORD)hModule);
                pFunname = new char[MAX_PATH];
                ReadProcessMemory(hProcess, (LPVOID)pFunnameVA, pFunname, MAX_PATH, &dwReadModuleSize);
                FunVA = GetProcAddressByFile(pDllname, pFunname + 2, hProcess, FunRVA);
                delete[]pFunname;
            }
            else
            {
                DWORD Ordinal = pInt->u1.Ordinal & 0x0000FFFF;
                FunVA = GetProcAddressByFile(pDllname, (LPCSTR)Ordinal, hProcess, FunRVA);
            }
            if (FunVA == pIat->u1.Function)
            {
                if (IMAGE_SNAP_BY_ORDINAL32(pInt->u1.AddressOfData) != 1)
                {
                    pFunnameVA = (char*)(pInt->u1.ForwarderString + (DWORD)hModule);
                    pFunname = new char[MAX_PATH];
                    ReadProcessMemory(hProcess, (LPVOID)pFunnameVA, pFunname, MAX_PATH, &dwReadModuleSize);
                    delete[]pFunname;
                }
            }
            else
            {
                if (IMAGE_SNAP_BY_ORDINAL32(pInt->u1.AddressOfData) != 1)
                {
                    char pTempDll[100] = { 0 };
                    char pTempFuction[100] = { 0 };
                    while (isforwardstring((char*)FunRVA))
                    {
                        strcpy(pTempDll, (char*)FunRVA);
                        char* p = strchr(pTempDll, '.');
                        *p = 0;
                        strcpy(pTempFuction, p + 1);
                        strcat(pTempDll, ".dll");
                        FunVA = GetProcAddressByFile(pTempDll, pTempFuction, hProcess, FunRVA);
                    }
                    if (FunVA == pIat->u1.Function)
                    {
                        // printf("%s��ת��\r\n", pTempFuction);
                    }
                    else
                    {
                        char* pFunnameVA1 = (char*)(pInt->u1.AddressOfData + (DWORD)hModule);
                        char* pFunname1 = new char[MAX_PATH];
                        ReadProcessMemory(hProcess, (LPVOID)pFunnameVA1, pFunname1, MAX_PATH, &dwReadModuleSize);
                        printf("%s!%s��Hook\r\n", pDllname, PIMAGE_IMPORT_BY_NAME(pFunname1)->Name);
                        delete[]pFunname1;
                    }
                }
            }
            pInt++;
            pIat++;
        }
        pImport++;
    }
    printf("�������\r\n");
}

int _tmain(int argc, _TCHAR* argv[])
{
    DWORD tmp = (DWORD)GetModuleHandle(NULL);
    CheckIAT(18944);// hardcode pid :(
    system("pause");
    return 0;
}


