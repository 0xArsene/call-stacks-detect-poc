//运行时检查当前程序指定地址函数的栈大小
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>


#pragma comment(lib, "dbghelp.lib")

// 对应 x64 Unwind Code 的联合体定义
typedef union _UNWIND_CODE {
	struct {
		BYTE CodeOffset;   // 机器码在 prolog 中的偏移量
		BYTE UnwindOp : 4; // 展开操作码 (如 UWOP_ALLOC_SMALL 等)
		BYTE OpInfo : 4;   // 操作码相关信息 (寄存器号或大小信息)
	} s;
	USHORT FrameOffset; // 某些操作码用于表示偏移量 (如大内存分配的低16位)
} UNWIND_CODE, * PUNWIND_CODE;

// 对应 x64 Unwind Info 的结构体定义
typedef struct _UNWIND_INFO {
	BYTE Version : 3;          // 版本号
	BYTE Flags : 5;            // 标志位 (如 UNW_FLAG_EHANDLER 等)
	BYTE SizeOfProlog;         // 整个 Prolog 的大小
	BYTE CountOfCodes;         // UnwindCode 数组的元素个数
	BYTE FrameRegister : 4;    // 如果使用了帧指针寄存器 (如 RBP)，表示其寄存器号
	BYTE FrameOffset : 4;      // 帧指针寄存器的偏移 (FrameOffset * 16)
	UNWIND_CODE UnwindCode[1]; // 展开码数组 (实际长度由 CountOfCodes 决定)
} UNWIND_INFO, * PUNWIND_INFO;

/*
 * 计算给定地址所在函数的栈大小 (手动解析 PE 头和 .pdata 异常表)
 * @param Address: 需要解析的函数内部地址
 * @return: 函数的栈大小 (以字节为单位)
 */
DWORD CalculateFunctionStackSize(DWORD64 Address) {
	HMODULE hModule = NULL;

	// -------------------------------------------------------------------
	// [DbgHelp] 解析目标地址的符号名称
	// -------------------------------------------------------------------
	{
		HANDLE hProcess = GetCurrentProcess();
		// SymInitialize 允许重复调用，失败时忽略（已初始化的进程不影响后续使用）
		SymInitialize(hProcess, NULL, TRUE);
		SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

		// SYMBOL_INFO 末尾需要额外空间存放符号名字符串
		char symBuf[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(CHAR)] = { 0 };
		PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symBuf;
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;

		DWORD64 displacement = 0;
		if (SymFromAddr(hProcess, Address, &displacement, pSymbol)) {
			printf("[*] 符号解析: 0x%llX -> %s + 0x%llX\n", Address, pSymbol->Name,
				displacement);
		}
		else {
			printf("[*] 符号解析: 0x%llX -> (无符号, GetLastError=%lu)\n", Address,
				GetLastError());
		}
	}
	// -------------------------------------------------------------------

	// 1. 获取目标地址所在的模块基址
	if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCSTR)Address, &hModule)) {
		printf("[-] 无法获取地址 0x%llX 所在的模块基址\n", Address);
		return 0;
	}

	DWORD64 modBase = (DWORD64)hModule;
	DWORD rvaRip = (DWORD)(Address - modBase);
	printf("[*] 开始计算地址 0x%llX 的栈大小\n", Address);
	printf("    [+] 所属模块基址: 0x%llX，相对偏移 (RVA): 0x%X\n", modBase,
		rvaRip);

	// 2. 手动解析 PE 头部以获取异常表 (.pdata) 目录
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)modBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] DOS 头签名错误\n");
		return 0;
	}

	PIMAGE_NT_HEADERS pNtHeaders =
		(PIMAGE_NT_HEADERS)(modBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-] NT 头签名错误\n");
		return 0;
	}

	// 3. 获取异常目录的 RVA 和大小
	DWORD exceptionRva =
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
		.VirtualAddress;
	DWORD exceptionSize =
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]
		.Size;

	if (exceptionRva == 0 || exceptionSize == 0) {
		printf("    [-] 当前模块没有 .pdata 异常表，地址为叶子函数或未记录函数\n");
		return 0;
	}

	// 4. 定位异常表，并进行线性/二分查找
	PRUNTIME_FUNCTION pTable = (PRUNTIME_FUNCTION)(modBase + exceptionRva);
	DWORD numEntries = exceptionSize / sizeof(RUNTIME_FUNCTION);
	PRUNTIME_FUNCTION pFound = NULL;
	DWORD foundIndex = 0;

	printf("    [+] 在异常表中搜索 (共有 %u 个条目)...\n", numEntries);
	for (DWORD i = 0; i < numEntries; i++) {
		if (rvaRip >= pTable[i].BeginAddress && rvaRip < pTable[i].EndAddress) {
			pFound = &pTable[i];
			foundIndex = i;
			break;
		}
	}

	if (!pFound) {
		printf("    [-] 未在 .pdata "
			"异常表中找到匹配条目。这是一个叶子函数，栈大小为 0\n\n");
		return 0;
	}

	printf("    [+] 匹配成功! (第 %u 个条目) BeginAddress: 0x%X, EndAddress: "
		"0x%X, UnwindData: "
		"0x%X\n",
		foundIndex, pFound->BeginAddress, pFound->EndAddress,
		pFound->UnwindData);

	// 5. 开始解析 UNWIND_INFO
	DWORD currentUnwindData = pFound->UnwindData;
	DWORD currentBeginAddress = pFound->BeginAddress;
	DWORD totalFrameSize = 0;
	BOOL bIsChained = FALSE;

	do {
		PUNWIND_INFO pUnwind = (PUNWIND_INFO)(modBase + currentUnwindData);

		if (bIsChained) {
			printf("    [+] 正在解析链式 UNWIND_INFO (BeginAddress: 0x%X)...\n",
				currentBeginAddress);
		}
		else {
			printf("    [+] 解析 %u 个 Unwind Codes...\n", pUnwind->CountOfCodes);
		}

		for (int i = 0; i < pUnwind->CountOfCodes; i++) {
			UNWIND_CODE code = pUnwind->UnwindCode[i];

			switch (code.s.UnwindOp) {
			case 0: // UWOP_PUSH_NONVOL (压栈非易失寄存器，如 push rbx)
				totalFrameSize += 8;
				printf("      [Code %d] UWOP_PUSH_NONVOL (Reg: %d) -> 栈大小 += 8 "
					"(当前: 0x%X)\n",
					i, code.s.OpInfo, totalFrameSize);
				break;

			case 1: // UWOP_ALLOC_LARGE (大内存分配)
				if (code.s.OpInfo == 0) {
					i++;
					DWORD allocSize = pUnwind->UnwindCode[i].FrameOffset * 8;
					totalFrameSize += allocSize;
					printf("      [Code %d] UWOP_ALLOC_LARGE (1 node) -> 栈大小 += 0x%X "
						"(当前: 0x%X)\n",
						i - 1, allocSize, totalFrameSize);
				}
				else {
					i += 2;
					DWORD allocSize = *(PDWORD)(&pUnwind->UnwindCode[i - 1]);
					totalFrameSize += allocSize;
					printf("      [Code %d] UWOP_ALLOC_LARGE (2 nodes) -> 栈大小 += 0x%X "
						"(当前: 0x%X)\n",
						i - 2, allocSize, totalFrameSize);
				}
				break;

			case 2: // UWOP_ALLOC_SMALL (小内存分配)
			{
				DWORD allocSize = (code.s.OpInfo * 8) + 8;
				totalFrameSize += allocSize;
				printf(
					"      [Code %d] UWOP_ALLOC_SMALL -> 栈大小 += 0x%X (当前: 0x%X)\n",
					i, allocSize, totalFrameSize);
			} break;

			case 3: // UWOP_SET_FPREG (建立帧指针)
				printf("      [Code %d] UWOP_SET_FPREG (Reg: %d) -> "
					"**按要求直接跳过该步骤**\n",
					i, pUnwind->FrameRegister);
				break;

			case 4: // UWOP_SAVE_NONVOL (保存非易失寄存器到栈上)
				printf("      [Code %d] UWOP_SAVE_NONVOL -> 不影响栈大小\n", i);
				i++;
				break;

			case 5: // UWOP_SAVE_NONVOL_FAR
				printf("      [Code %d] UWOP_SAVE_NONVOL_FAR -> 不影响栈大小\n", i);
				i += 2;
				break;

			case 6: // UWOP_EPILOG
				printf("      [Code %d] UWOP_EPILOG -> 不影响栈大小\n", i);
				i++;
				break;

			case 8: // UWOP_SAVE_XMM128
				printf("      [Code %d] UWOP_SAVE_XMM128 -> 不影响栈大小\n", i);
				i++;
				break;

			case 9: // UWOP_SAVE_XMM128_FAR
				printf("      [Code %d] UWOP_SAVE_XMM128_FAR -> 不影响栈大小\n", i);
				i += 2;
				break;

			case 10: // UWOP_PUSH_MACHFRAME
			{
				DWORD pushSize = (code.s.OpInfo == 0) ? 40 : 48;
				totalFrameSize += pushSize;
				printf("      [Code %d] UWOP_PUSH_MACHFRAME -> 栈大小 += 0x%X (当前: "
					"0x%X)\n",
					i, pushSize, totalFrameSize);
			} break;

			default:
				printf("      [Code %d] 未知操作码 (Opcode: %d)\n", i, code.s.UnwindOp);
				break;
			}
		}

		// 链式处理
		if (pUnwind->Flags & 0x04) {
			int alignedCount = (pUnwind->CountOfCodes + 1) & ~1;
			PRUNTIME_FUNCTION pChainedFunc =
				(PRUNTIME_FUNCTION)(&pUnwind->UnwindCode[alignedCount]);

			printf(
				"    [*] 检测到 UNW_FLAG_CHAININFO，准备追踪至 BeginAddress: 0x%X\n",
				pChainedFunc->BeginAddress);

			currentUnwindData = pChainedFunc->UnwindData;
			currentBeginAddress = pChainedFunc->BeginAddress;
			bIsChained = TRUE;
		}
		else {
			break;
		}

	} while (TRUE);

	printf("[+] 最终计算完成！该函数的总栈大小为: 0x%X (%u) 字节\n",
		totalFrameSize, totalFrameSize);
	printf("=========================================================\n\n");
	return totalFrameSize;
}

// 简单测试
int main() {
	//直接输入地址
	CalculateFunctionStackSize(0x00007FFD71FB5321);

	//传递函数地址
	HMODULE hKernelBase = GetModuleHandleA("kernel32.dll");
	if (hKernelBase) {
		FARPROC func = GetProcAddress(hKernelBase, "BaseThreadInitThunk");
		CalculateFunctionStackSize((DWORD64)func);
	}
	else {
		printf("无法获取句柄\n");
	}

	return 0;
}
