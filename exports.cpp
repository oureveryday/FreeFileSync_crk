#include "exports.h"
#include <stdio.h>
#include <windows.h>

FARPROC OriginalFuncs[17];


void Load()
{
    char szSystemDirectory[MAX_PATH] = {0};
    GetSystemDirectoryA(szSystemDirectory, MAX_PATH);
    
    char OriginalPath[MAX_PATH] = {0};
    snprintf(OriginalPath, MAX_PATH, "%s\\version.dll", szSystemDirectory);
        
    HMODULE version = LoadLibraryA(OriginalPath);
    if (!version) {
        MessageBoxA(NULL, "Failed to load version.dll from system32\n", "Error", MB_ICONERROR);
        return;
    }
        
    for (int i = 0; i < 17; i++) {
        OriginalFuncs[i] = GetProcAddress(version, ExportNames[i]);
        if (!OriginalFuncs[i])
        {
            continue;
        }
    }
}
