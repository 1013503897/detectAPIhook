#pragma once
#include "windows.h"
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>

typedef struct _MODULE_INFO
{
    char FileFullPath[MAX_PATH];
    DWORD ImageBase;
}MODULE_INFO, * PMODULE_INFO;

DWORD RvaToOffset(PBYTE pPeFile, DWORD Rva);
void mytoupper(char* str);
DWORD GetProcAddressByFile(LPCSTR lpDllName, LPCSTR lpProcName, HANDLE hProcess, DWORD& FOAFunction);
bool isforwardstring(char* str);
void CheckIAT(DWORD dwProcessID);
void CheckEAT(DWORD dwProcessID);
HMODULE GetRemoteImageBase(DWORD dwProcessID);
VOID GetRemoteModuleInfo(DWORD dwProcessID);