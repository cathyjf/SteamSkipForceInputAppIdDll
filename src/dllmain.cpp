/**
 * This file is a part of the cathyjf/SteamSkipForceInputAppIdDll project.
 * Copyright 2022 Cathy J. Fitzpatrick (https://cathyjf.com).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see [https://www.gnu.org/licenses/].
 **/

#include "pch.h"
#include "detours.h"

#include <shellapi.h>
#include <string_view>

namespace {

auto RealCreateProcessW = CreateProcessW;

BOOL ReplacementCreateProcessW(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation) {
    const auto view = std::wstring_view{ lpCommandLine };
    if (view.find(L"steam.exe -- steam://forceinputappid/") != std::wstring_view::npos) {
        return FALSE;
    }
    return RealCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation);
}

} // anonymous namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        DetourTransactionBegin();

        // Versions of SpecialK on or after 01/22/2024 use CreateProcessW to invoke `steam://forceinputappid`.
        // See https://github.com/SpecialKO/SpecialK/commit/8347b3af.
        DetourAttach(reinterpret_cast<void **>(&RealCreateProcessW), ReplacementCreateProcessW);

        const auto error = DetourTransactionCommit();
        if (error != NO_ERROR) {
            return FALSE;
        }
    } break;
    case DLL_PROCESS_DETACH: {
        DetourTransactionBegin();
        DetourDetach(reinterpret_cast<void **>(&RealCreateProcessW), ReplacementCreateProcessW);
        DetourTransactionCommit();
    } break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}