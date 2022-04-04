// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "detours.h"
#include <shellapi.h>
#include <string>
#include <typeinfo>

namespace {

auto RealShellExecuteA = ShellExecuteA;
auto RealShellExecuteW = ShellExecuteW;

#define FORBIDDEN_PREFIX(x) x ## "steam://forceinputappid/"

#pragma warning(push)
#pragma warning(disable : 6276)

template <class T>
bool isForbiddenExecution(const T *lpFile) {
    const std::basic_string<T> file{ lpFile };
    constexpr T *cstrPrefix{
            std::is_same<T, char>::value ?
                (T *const)FORBIDDEN_PREFIX("") : (T *const)FORBIDDEN_PREFIX(L) };
    return (file.find(cstrPrefix) == 0);
}

#pragma warning(pop)

HINSTANCE ReplacementShellExecuteA(
        _In_opt_ HWND hwnd, _In_opt_ LPCSTR lpOperation, _In_ LPCSTR lpFile, _In_opt_ LPCSTR lpParameters,
        _In_opt_ LPCSTR lpDirectory, _In_ INT nShowCmd) {
    if (isForbiddenExecution(lpFile)) {
        return 0;
    }
    return RealShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

HINSTANCE ReplacementShellExecuteW(
        _In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpOperation, _In_ LPCWSTR lpFile, _In_opt_ LPCWSTR lpParameters,
        _In_opt_ LPCWSTR lpDirectory, _In_ INT nShowCmd) {
    if (isForbiddenExecution(lpFile)) {
        return 0;
    }
    return RealShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
}

} // anonymous namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(reinterpret_cast<PVOID *>(&RealShellExecuteA), ReplacementShellExecuteA);
        DetourAttach(reinterpret_cast<PVOID *>(&RealShellExecuteW), ReplacementShellExecuteW);
        const LONG error{ DetourTransactionCommit() };
        if (error != NO_ERROR) {
            return FALSE;
        }
    } break;
    case DLL_PROCESS_DETACH: {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(reinterpret_cast<PVOID *>(&RealShellExecuteA), ReplacementShellExecuteA);
        DetourDetach(reinterpret_cast<PVOID *>(&RealShellExecuteW), ReplacementShellExecuteW);
        DetourTransactionCommit();
    } break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}