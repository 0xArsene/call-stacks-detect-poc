#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>


typedef union _UNWIND_CODE {
  struct {
    BYTE CodeOffset;
    BYTE UnwindOp : 4;
    BYTE OpInfo : 4;
  } s;
  USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
  BYTE Version : 3;
  BYTE Flags : 5;
  BYTE SizeOfProlog;
  BYTE CountOfCodes;
  BYTE FrameRegister : 4;
  BYTE FrameOffset : 4;
  UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

DWORD64 GetModuleBaseFromRip(DWORD dwProcessId, DWORD64 Rip,
                             WCHAR *outModuleName) {
  HANDLE hSnap = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwProcessId);
  if (hSnap == INVALID_HANDLE_VALUE)
    return 0;

  MODULEENTRY32W me = {sizeof(MODULEENTRY32W)};
  if (Module32FirstW(hSnap, &me)) {
    do {
      DWORD64 modBase = (DWORD64)me.modBaseAddr;
      DWORD64 modEnd = modBase + me.modBaseSize;
      if (Rip >= modBase && Rip < modEnd) {
        wcscpy_s(outModuleName, MAX_PATH, me.szModule);
        CloseHandle(hSnap);
        return modBase;
      }
    } while (Module32NextW(hSnap, &me));
  }
  CloseHandle(hSnap);
  return 0;
}

void PhantomWalker(DWORD dwThreadId) {
  HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME |
                                  THREAD_QUERY_INFORMATION,
                              FALSE, dwThreadId);
  if (!hThread) {
    wprintf(L"[-] Failed to open thread.\n");
    return;
  }

  DWORD dwProcessId = GetProcessIdOfThread(hThread);
  if (dwProcessId == 0) {
    wprintf(L"[-] Failed to get process ID from thread.\n");
    CloseHandle(hThread);
    return;
  }

  HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                                FALSE, dwProcessId);
  if (!hProcess) {
    wprintf(L"[-] Failed to open process.\n");
    CloseHandle(hThread);
    return;
  }

  SuspendThread(hThread);
  CONTEXT ctx = {0};
  ctx.ContextFlags = CONTEXT_CONTROL;
  if (!GetThreadContext(hThread, &ctx)) {
    wprintf(L"[-] GetThreadContext failed.\n");
    ResumeThread(hThread);
    return;
  }

  DWORD64 currentRip = ctx.Rip;
  DWORD64 currentRsp = ctx.Rsp;

  wprintf(L"[*] Starting RPM Stack Walk (PID: %u, TID: %u)\n", dwProcessId,
          dwThreadId);
  wprintf(L"==========================================================\n");

  for (int frame = 0; frame < 20; frame++) {
    if (currentRip == 0)
      break;

    WCHAR modName[MAX_PATH] = {0};
    DWORD64 modBase = GetModuleBaseFromRip(dwProcessId, currentRip, modName);

    if (modBase == 0) {
      wprintf(L"[%02d] RIP: 0x%I64X (No module found. Possibly JIT/Shellcode "
              L"or End of Stack)\n",
              frame, currentRip);

      ReadProcessMemory(hProcess, (LPCVOID)currentRsp, &currentRip, 8, NULL);
      currentRsp += 8;
      continue;
    }

    DWORD rvaRip = (DWORD)(currentRip - modBase);
    wprintf(L"[%02d] RIP: 0x%I64X | RSP: 0x%I64X | Module: %s (+0x%X)\n", frame,
            currentRip, currentRsp, modName, rvaRip);

    IMAGE_DOS_HEADER dosHeader = {0};
    ReadProcessMemory(hProcess, (LPCVOID)modBase, &dosHeader,
                      sizeof(IMAGE_DOS_HEADER), NULL);

    IMAGE_NT_HEADERS64 ntHeaders = {0};
    ReadProcessMemory(hProcess, (LPCVOID)(modBase + dosHeader.e_lfanew),
                      &ntHeaders, sizeof(IMAGE_NT_HEADERS64), NULL);

    DWORD exceptionRva =
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .VirtualAddress;
    DWORD exceptionSize =
        ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
            .Size;

    if (exceptionRva == 0 || exceptionSize == 0) {
      wprintf(L"    [-] No .pdata found. Assuming Leaf Function.\n");
      ReadProcessMemory(hProcess, (LPCVOID)currentRsp, &currentRip, 8, NULL);
      currentRsp += 8;
      continue;
    }

    DWORD numEntries = exceptionSize / sizeof(RUNTIME_FUNCTION);
    PRUNTIME_FUNCTION pTable = (PRUNTIME_FUNCTION)malloc(exceptionSize);
    ReadProcessMemory(hProcess, (LPCVOID)(modBase + exceptionRva), pTable,
                      exceptionSize, NULL);

    PRUNTIME_FUNCTION pFound = NULL;
    for (DWORD i = 0; i < numEntries; i++) {
      if (rvaRip >= pTable[i].BeginAddress && rvaRip < pTable[i].EndAddress) {
        pFound = &pTable[i];
        break;
      }
    }

    if (!pFound) {
      wprintf(L"    [-] Not found in .pdata. Assuming Leaf Function.\n");
      ReadProcessMemory(hProcess, (LPCVOID)currentRsp, &currentRip, 8, NULL);
      currentRsp += 8;
      free(pTable);
      continue;
    }

    DWORD currentUnwindData = pFound->UnwindData;
    DWORD currentBeginAddress = pFound->BeginAddress;
    DWORD totalFrameSize = 0;
    BOOL bIsChained = FALSE;

    do {
      BYTE unwindBuffer[1024] = {0};
      if (!ReadProcessMemory(hProcess, (LPCVOID)(modBase + currentUnwindData),
                             unwindBuffer, sizeof(unwindBuffer), NULL)) {
        wprintf(L"    [-] Failed to read UNWIND_INFO at RVA 0x%X\n",
                currentUnwindData);
        break;
      }
      PUNWIND_INFO pUnwind = (PUNWIND_INFO)unwindBuffer;

      DWORD funcOffset = rvaRip - currentBeginAddress;

      if (bIsChained) {
        wprintf(
            L"    [+] Parsing Chained UNWIND_INFO (BeginAddress: 0x%X)...\n",
            currentBeginAddress);
      } else {
        wprintf(L"    [+] Parsing %u Unwind Codes (funcOffset: 0x%X)...\n",
                pUnwind->CountOfCodes, funcOffset);
      }

      for (int i = 0; i < pUnwind->CountOfCodes; i++) {
        UNWIND_CODE code = pUnwind->UnwindCode[i];

        BOOL isExecuted = bIsChained ? TRUE : (funcOffset >= code.s.CodeOffset);

        switch (code.s.UnwindOp) {
        case 0:
          if (isExecuted)
            totalFrameSize += 8;
          break;

        case 1:
          if (code.s.OpInfo == 0) {
            i++;
            if (isExecuted)
              totalFrameSize += pUnwind->UnwindCode[i].FrameOffset * 8;
          } else {
            i += 2;
            if (isExecuted)
              totalFrameSize += *(PDWORD)(&pUnwind->UnwindCode[i - 1]);
          }
          break;

        case 2:
          if (isExecuted)
            totalFrameSize += (code.s.OpInfo * 8) + 8;
          break;

        case 3:
          break;

        case 4:
          i++;
          break;

        case 5:
          i += 2;
          break;

        case 6:
          i++;
          break;

        case 8:
          i++;
          break;

        case 9:
          i += 2;
          break;

        case 10:
          if (isExecuted)
            totalFrameSize += (code.s.OpInfo == 0) ? 40 : 48;
          break;

        default:
          break;
        }
      }

      if (pUnwind->Flags & 0x04) {
        int alignedCount = (pUnwind->CountOfCodes + 1) & ~1;

        PRUNTIME_FUNCTION pChainedFunc =
            (PRUNTIME_FUNCTION)(&pUnwind->UnwindCode[alignedCount]);

        wprintf(L"    [*] UNW_FLAG_CHAININFO detected. Chaining to "
                L"BeginAddress: 0x%X\n",
                pChainedFunc->BeginAddress);

        currentUnwindData = pChainedFunc->UnwindData;
        currentBeginAddress = pChainedFunc->BeginAddress;
        bIsChained = TRUE;
      } else {
        break;
      }

    } while (TRUE);

    currentRsp += totalFrameSize;

    DWORD64 nextRip = 0;
    ReadProcessMemory(hProcess, (LPCVOID)currentRsp, &nextRip, 8, NULL);

    wprintf(
        L"    [+] Successfully resolved Return Address (Next RIP): 0x%I64X\n\n",
        nextRip);

    currentRip = nextRip;
    currentRsp += 8;

    free(pTable);
  }

  wprintf(L"==========================================================\n");
  wprintf(L"[*] Stack Walk Completed.\n");

  ResumeThread(hThread);
  CloseHandle(hThread);
  CloseHandle(hProcess);
}

int wmain(int argc, wchar_t *argv[]) {
  if (argc != 2) {
    wprintf(L"Usage: %s <TID>\n", argv[0]);
    return 1;
  }

  DWORD tid = _wtol(argv[1]);

  PhantomWalker(tid);
  return 0;
}
