#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <iostream>

#include "MinHook.h"
#include "Sig.hpp"
#include "exports.h"

typedef struct
{
    uint64_t type;
    uint64_t data;
} lic_data;

typedef void (*lic_check_t)();
lic_check_t olic_check = nullptr;

typedef lic_data* (*get_lic_data_t)();
get_lic_data_t oget_lic_data = nullptr;

lic_data* get_lic_data() {
    lic_data *data = oget_lic_data();
    data->type = 0x2; // Donation Version
    data->data = 0x0;
    return data;
}

void lic_check()
{
    return;
}

void Hook() {
    const auto exe = GetModuleHandle(NULL);
    const auto header = (PIMAGE_DOS_HEADER)exe;
    const auto nt = (PIMAGE_NT_HEADERS)((uint8_t *)exe + header->e_lfanew);
    const auto size = nt->OptionalHeader.SizeOfImage;

	{
        const void *found = Sig::find(exe, size, "48 89 5C 24 ?? 48 89 74 24 ?? 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 4C 8B E1 48 89 4C 24 ?? 45 33 ED 44 89 6C 24 ?? 48 8D 4C 24 ??");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)get_lic_data, (LPVOID *)&oget_lic_data);
            MH_EnableHook((LPVOID)found);
        }
        else
        {
            MessageBoxA(NULL, "Failed to find get_lic_data", "Error", MB_ICONERROR);
        }
    }

    {
        const void *found = Sig::find(exe, size, "48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 56 48 8D AC 24 ?? ?? ?? ?? 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 85 ?? ?? ?? ?? 48 8B D9 33 FF 8B 01 83 E8 ??");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)lic_check, (LPVOID *)&olic_check);
            MH_EnableHook((LPVOID)found);
        }
        else
        {
            MessageBoxA(NULL, "Failed to find lic_check", "Error", MB_ICONERROR);
        }
    }
}


void start() {
    MH_Initialize();
    Hook();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        char processName[MAX_PATH];
        GetModuleFileNameA(NULL, processName, MAX_PATH);
        
        char* fileName = strrchr(processName, '\\');
        fileName = fileName ? fileName + 1 : processName;
        
        if (_stricmp(fileName, "FreeFileSync_x64.exe") == 0) {
            start();
        }
    }

    return true;
}

__declspec(dllexport) void __cdecl Crack(void)
{
    ;
}

bool TlsOnce = false;
// this runs way before dllmain
void __stdcall TlsCallback(PVOID hModule, DWORD fdwReason, PVOID pContext)
{
	if (!TlsOnce)
	{
		Load();
		TlsOnce = true;
	}
}

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;