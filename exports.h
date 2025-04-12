#pragma once
#include <Windows.h>

extern "C" FARPROC OriginalFuncs[17];

inline LPCSTR ExportNames[] = {
		"GetFileVersionInfoA",
		"GetFileVersionInfoByHandle",
		"GetFileVersionInfoExA",
		"GetFileVersionInfoExW",
		"GetFileVersionInfoSizeA",
		"GetFileVersionInfoSizeExA",
		"GetFileVersionInfoSizeExW",
		"GetFileVersionInfoSizeW",
		"GetFileVersionInfoW",
		"VerFindFileA",
		"VerFindFileW",
		"VerInstallFileA",
		"VerInstallFileW",
		"VerLanguageNameA",
		"VerLanguageNameW",
		"VerQueryValueA",
		"VerQueryValueW"
};

void Load();