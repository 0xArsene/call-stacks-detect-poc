#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

BOOL PrintThreadStack(IN DWORD dwTid) {
    HANDLE hThread = NULL;
    HANDLE hProcess = NULL;
    DWORD dwPid = 0;
    BOOL bResult = FALSE;
    BOOL bSymInitialized = FALSE;
    CONTEXT contextRecord = { 0 };
    STACKFRAME64 stackFrame = { 0 };
    DWORD dwMachineType = 0;

    hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
        THREAD_QUERY_INFORMATION,
        FALSE, dwTid);
    if (hThread == NULL) {
        wprintf(L"[!] OpenThread failed: %u\n", GetLastError());
        return FALSE;
    }

    dwPid = GetProcessIdOfThread(hThread);
    if (dwPid == 0) {
        wprintf(L"[!] GetProcessIdOfThread failed: %u\n", GetLastError());
        goto Cleanup;
    }

    hProcess =
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);
    if (hProcess == NULL) {
        wprintf(L"[!] OpenProcess failed: %u\n", GetLastError());
        goto Cleanup;
    }

    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
    if (!SymInitialize(hProcess, NULL, TRUE)) {
        wprintf(L"[!] SymInitialize failed: %u\n", GetLastError());
        goto Cleanup;
    }
    bSymInitialized = TRUE;

    if (SuspendThread(hThread) == (DWORD)-1) {
        wprintf(L"[!] SuspendThread failed: %u\n", GetLastError());
        goto Cleanup;
    }

    contextRecord.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &contextRecord)) {
        wprintf(L"[!] GetThreadContext failed: %u\n", GetLastError());
        ResumeThread(hThread);
        goto Cleanup;
    }

    ResumeThread(hThread);

    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;

#if defined(_AMD64_)
    dwMachineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = contextRecord.Rip;
    stackFrame.AddrStack.Offset = contextRecord.Rsp;
    stackFrame.AddrFrame.Offset = contextRecord.Rbp;
#elif defined(_IA64_)
    dwMachineType = IMAGE_FILE_MACHINE_IA64;
    stackFrame.AddrPC.Offset = contextRecord.StIIP;
    stackFrame.AddrStack.Offset = contextRecord.IntSp;
    stackFrame.AddrFrame.Offset = contextRecord.RsBSP;
#else
    dwMachineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = contextRecord.Eip;
    stackFrame.AddrStack.Offset = contextRecord.Esp;
    stackFrame.AddrFrame.Offset = contextRecord.Ebp;
#endif

    wprintf(L"  # | Function Name                                     | Return "
        L"Address     | Stack Address     \n");
    wprintf(L"----+---------------------------------------------------+----------"
        L"----------+-------------------\n");

    DWORD dwFrameIndex = 0;
    while (StackWalk64(dwMachineType, hProcess, hThread, &stackFrame,
        &contextRecord, NULL, SymFunctionTableAccess64,
        SymGetModuleBase64, NULL)) {
        if (stackFrame.AddrPC.Offset == 0) {
            break;
        }

        WCHAR szFuncName[MAX_SYM_NAME] = L"UnknownFunction";
        DWORD64 dwDisplacement = 0;

        BYTE buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR)] = { 0 };
        PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        if (SymFromAddrW(hProcess, stackFrame.AddrPC.Offset, &dwDisplacement,
            pSymbol)) {
            wcscpy_s(szFuncName, MAX_SYM_NAME, pSymbol->Name);
        }
        else {
            IMAGEHLP_MODULEW64 moduleInfo = { 0 };
            moduleInfo.SizeOfStruct = sizeof(IMAGEHLP_MODULEW64);
            if (SymGetModuleInfoW64(hProcess, stackFrame.AddrPC.Offset,
                &moduleInfo)) {
                swprintf_s(szFuncName, MAX_SYM_NAME, L"%s+0x%llx",
                    moduleInfo.ModuleName,
                    stackFrame.AddrPC.Offset - moduleInfo.BaseOfImage);
            }
            else {
                swprintf_s(szFuncName, MAX_SYM_NAME, L"0x%llx",
                    stackFrame.AddrPC.Offset);
            }
        }

        WCHAR szLineInfo[512] = L"";
        IMAGEHLP_LINEW64 line = { 0 };
        line.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
        DWORD dwDisplacementLine = 0;
        if (SymGetLineFromAddrW64(hProcess, stackFrame.AddrPC.Offset,
            &dwDisplacementLine, &line)) {
            PWCHAR pszFileName = wcsrchr(line.FileName, L'\\');
            pszFileName = (pszFileName != NULL) ? pszFileName + 1 : line.FileName;
            swprintf_s(szLineInfo, 512, L" [%s:%u]", pszFileName, line.LineNumber);
        }

        WCHAR szFullSymbol[1024] = { 0 };
        swprintf_s(szFullSymbol, 1024, L"%s%s", szFuncName, szLineInfo);

        wprintf(L" %2u | %-49s | 0x%016llx | 0x%016llx\n", dwFrameIndex,
            szFullSymbol, stackFrame.AddrReturn.Offset,
            stackFrame.AddrStack.Offset);

        // Check if the current frame lies in executable private memory (possible
        // shellcode)
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (VirtualQueryEx(hProcess, (LPCVOID)stackFrame.AddrPC.Offset, &mbi,
            sizeof(mbi))) {
            BOOL bSuspicious = FALSE;

            if (mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT) {
                if (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ ||
                    mbi.Protect == PAGE_EXECUTE_READWRITE ||
                    mbi.Protect == PAGE_EXECUTE_WRITECOPY) {
                    bSuspicious = TRUE;
                }
            }

            if (bSuspicious) {
                wprintf(L"        [!] DETECTED: Executable Private Memory (Possible "
                    L"Shellcode!)\n");
                wprintf(L"            BaseAddress: 0x%p, RegionSize: 0x%llx, Protect: "
                    L"0x%X\n",
                    mbi.BaseAddress, (ULONGLONG)mbi.RegionSize, mbi.Protect);

                SIZE_T dwDumpSize = mbi.RegionSize;
                if (dwDumpSize > 1024 * 1024) {
                    dwDumpSize = 1024 * 1024;
                }

                PBYTE lpDumpBuffer =
                    (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDumpSize);
                if (lpDumpBuffer != NULL) {
                    SIZE_T dwBytesRead = 0;
                    if (ReadProcessMemory(hProcess, mbi.BaseAddress, lpDumpBuffer,
                        dwDumpSize, &dwBytesRead)) {
                        wprintf(L"            Hex Preview: ");
                        for (SIZE_T i = 0; i < (dwBytesRead < 16 ? dwBytesRead : 16); i++) {
                            wprintf(L"%02X ", lpDumpBuffer[i]);
                        }
                        wprintf(L"\n");

                        WCHAR szDumpFileName[MAX_PATH] = { 0 };
                        swprintf_s(szDumpFileName, MAX_PATH, L"dump_%u_0x%p.bin", dwTid,
                            mbi.BaseAddress);

                        HANDLE hDumpFile =
                            CreateFileW(szDumpFileName, GENERIC_WRITE, 0, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hDumpFile != INVALID_HANDLE_VALUE) {
                            DWORD dwBytesWritten = 0;
                            WriteFile(hDumpFile, lpDumpBuffer, (DWORD)dwBytesRead,
                                &dwBytesWritten, NULL);
                            CloseHandle(hDumpFile);
                            wprintf(L"            [+] Memory dumped to: %s (%u bytes)\n",
                                szDumpFileName, dwBytesWritten);
                        }
                        else {
                            wprintf(
                                L"            [-] Failed to create dump file. Error: %u\n",
                                GetLastError());
                        }
                    }
                    else {
                        wprintf(L"            [-] ReadProcessMemory failed. Error: %u\n",
                            GetLastError());
                    }
                    HeapFree(GetProcessHeap(), 0, lpDumpBuffer);
                }
            }
        }

        dwFrameIndex++;
    }

    bResult = TRUE;

Cleanup:
    if (bSymInitialized) {
        SymCleanup(hProcess);
    }
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }
    if (hThread != NULL) {
        CloseHandle(hThread);
    }

    return bResult;
}

INT wmain(IN INT argc, IN WCHAR* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <TID>\n", argv[0]);
        return 1;
    }

    DWORD dwTid = wcstoul(argv[1], NULL, 10);
    if (dwTid == 0) {
        wprintf(L"[!] Invalid TID specified.\n");
        return 1;
    }

    wprintf(L"[*] Starting stack walk for Thread ID: %u ...\n\n", dwTid);
    if (!PrintThreadStack(dwTid)) {
        wprintf(L"[!] Stack walk failed.\n");
        return 1;
    }

    return 0;
}
