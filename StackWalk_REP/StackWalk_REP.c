#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#define DEBUG_UNWIND

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

DWORD64 GetContextRegister(PCONTEXT ctx, BYTE regIndex) {
  switch (regIndex) {
  case 0:
    return ctx->Rax;
  case 1:
    return ctx->Rcx;
  case 2:
    return ctx->Rdx;
  case 3:
    return ctx->Rbx;
  case 4:
    return ctx->Rsp;
  case 5:
    return ctx->Rbp;
  case 6:
    return ctx->Rsi;
  case 7:
    return ctx->Rdi;
  case 8:
    return ctx->R8;
  case 9:
    return ctx->R9;
  case 10:
    return ctx->R10;
  case 11:
    return ctx->R11;
  case 12:
    return ctx->R12;
  case 13:
    return ctx->R13;
  case 14:
    return ctx->R14;
  case 15:
    return ctx->R15;
  }
  return 0;
}

void SetContextRegister(PCONTEXT ctx, BYTE regIndex, DWORD64 value) {
  switch (regIndex) {
  case 0:
    ctx->Rax = value;
    break;
  case 1:
    ctx->Rcx = value;
    break;
  case 2:
    ctx->Rdx = value;
    break;
  case 3:
    ctx->Rbx = value;
    break;
  case 4:
    ctx->Rsp = value;
    break;
  case 5:
    ctx->Rbp = value;
    break;
  case 6:
    ctx->Rsi = value;
    break;
  case 7:
    ctx->Rdi = value;
    break;
  case 8:
    ctx->R8 = value;
    break;
  case 9:
    ctx->R9 = value;
    break;
  case 10:
    ctx->R10 = value;
    break;
  case 11:
    ctx->R11 = value;
    break;
  case 12:
    ctx->R12 = value;
    break;
  case 13:
    ctx->R13 = value;
    break;
  case 14:
    ctx->R14 = value;
    break;
  case 15:
    ctx->R15 = value;
    break;
  }
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
  CONTEXT originalCtx = {0};
  originalCtx.ContextFlags =
      CONTEXT_CONTROL | CONTEXT_INTEGER;
  if (!GetThreadContext(hThread, &originalCtx)) {
    wprintf(L"[-] GetThreadContext failed.\n");
    ResumeThread(hThread);
    return;
  }

  CONTEXT unwindCtx = originalCtx;
  DWORD64 currentRip = unwindCtx.Rip;
  DWORD64 currentRsp = unwindCtx.Rsp;

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
      unwindCtx.Rip = currentRip;
      unwindCtx.Rsp = currentRsp;
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
      unwindCtx.Rip = currentRip;
      unwindCtx.Rsp = currentRsp;
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
      unwindCtx.Rip = currentRip;
      unwindCtx.Rsp = currentRsp;
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
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_PUSH_NONVOL (Reg: %d). %s\n", i,
                  code.s.OpInfo, isExecuted ? L"Executed" : L"Skipped");
#endif
          if (isExecuted) {
            DWORD64 savedRegValue = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(currentRsp + totalFrameSize),
                              &savedRegValue, 8, NULL);
            SetContextRegister(&unwindCtx, code.s.OpInfo, savedRegValue);
            totalFrameSize += 8;
#ifdef DEBUG_UNWIND
            wprintf(L"        -> Restored Reg[%d] = 0x%I64X, totalFrameSize = "
                    L"0x%X\n",
                    code.s.OpInfo, savedRegValue, totalFrameSize);
#endif
          }
          break;

        case 1:
          if (code.s.OpInfo == 0) {
#ifdef DEBUG_UNWIND
            wprintf(L"      [Code %d] UWOP_ALLOC_LARGE (1 node). %s\n", i,
                    isExecuted ? L"Executed" : L"Skipped");
#endif
            i++;
            if (isExecuted) {
              totalFrameSize += pUnwind->UnwindCode[i].FrameOffset * 8;
#ifdef DEBUG_UNWIND
              wprintf(L"        -> totalFrameSize = 0x%X\n", totalFrameSize);
#endif
            }
          } else {
#ifdef DEBUG_UNWIND
            wprintf(L"      [Code %d] UWOP_ALLOC_LARGE (2 nodes). %s\n", i,
                    isExecuted ? L"Executed" : L"Skipped");
#endif
            i += 2;
            if (isExecuted) {
              totalFrameSize += *(PDWORD)(&pUnwind->UnwindCode[i - 1]);
#ifdef DEBUG_UNWIND
              wprintf(L"        -> totalFrameSize = 0x%X\n", totalFrameSize);
#endif
            }
          }
          break;

        case 2:
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_ALLOC_SMALL (Size: 0x%X). %s\n", i,
                  (code.s.OpInfo * 8) + 8,
                  isExecuted ? L"Executed" : L"Skipped");
#endif
          if (isExecuted) {
            totalFrameSize +=
                (code.s.OpInfo * 8) + 8;
#ifdef DEBUG_UNWIND
            wprintf(L"        -> totalFrameSize = 0x%X\n", totalFrameSize);
#endif
          }
          break;

        case 3:

#ifdef DEBUG_UNWIND
          wprintf(
              L"      [Code %d] UWOP_SET_FPREG (Reg: %d, Offset: 0x%X). %s\n",
              i, pUnwind->FrameRegister, pUnwind->FrameOffset * 16,
              isExecuted ? L"Executed" : L"Skipped");
#endif
          if (isExecuted) {
            DWORD64 frameRegValue =
                GetContextRegister(&unwindCtx, pUnwind->FrameRegister);

            currentRsp = frameRegValue - (pUnwind->FrameOffset * 16);

            totalFrameSize = 0;
#ifdef DEBUG_UNWIND
            wprintf(L"        -> HARD RESET: currentRsp = 0x%I64X (RegValue "
                    L"0x%I64X), totalFrameSize = 0\n",
                    currentRsp, frameRegValue);
#endif
          }
          break;

        case 4:

#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_SAVE_NONVOL (Reg: %d). %s\n", i,
                  code.s.OpInfo, isExecuted ? L"Executed" : L"Skipped");
#endif
          if (isExecuted) {
            DWORD offset = pUnwind->UnwindCode[i + 1].FrameOffset * 8;
            DWORD64 savedRegValue = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(currentRsp + offset),
                              &savedRegValue, 8, NULL);
            SetContextRegister(&unwindCtx, code.s.OpInfo, savedRegValue);
#ifdef DEBUG_UNWIND
            wprintf(L"        -> Restored Reg[%d] = 0x%I64X from [RSP+0x%X]\n",
                    code.s.OpInfo, savedRegValue, offset);
#endif
          }
          i++;
          break;

        case 5:
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_SAVE_NONVOL_FAR (Reg: %d). %s\n", i,
                  code.s.OpInfo, isExecuted ? L"Executed" : L"Skipped");
#endif
          if (isExecuted) {
            DWORD offset = *(PDWORD)(&pUnwind->UnwindCode[i + 1]);
            DWORD64 savedRegValue = 0;
            ReadProcessMemory(hProcess, (LPCVOID)(currentRsp + offset),
                              &savedRegValue, 8, NULL);
            SetContextRegister(&unwindCtx, code.s.OpInfo, savedRegValue);
#ifdef DEBUG_UNWIND
            wprintf(L"        -> Restored Reg[%d] = 0x%I64X from [RSP+0x%X]\n",
                    code.s.OpInfo, savedRegValue, offset);
#endif
          }
          i += 2;

          break;

        case 6:
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_EPILOG.\n", i);
#endif
          i++;
          break;

        case 8:
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_SAVE_XMM128.\n", i);
#endif
          i++;
          break;

        case 9:
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_SAVE_XMM128_FAR.\n", i);
#endif
          i +=
              2;
          break;

        case 10:
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UWOP_PUSH_MACHFRAME. %s\n", i,
                  isExecuted ? L"Executed" : L"Skipped");
#endif
          if (isExecuted) {

            totalFrameSize += (code.s.OpInfo == 0) ? 40 : 48;
#ifdef DEBUG_UNWIND
            wprintf(L"        -> totalFrameSize = 0x%X\n", totalFrameSize);
#endif
          }
          break;

        default:
#ifdef DEBUG_UNWIND
          wprintf(L"      [Code %d] UNKNOWN Opcode %d\n", i, code.s.UnwindOp);
#endif

          break;
        }
      }

      if (pUnwind->Flags & 0x04 ) {

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

    unwindCtx.Rip = currentRip;
    unwindCtx.Rsp = currentRsp;

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
