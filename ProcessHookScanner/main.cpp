#include"main.h"


// 获取进程的状态,排除僵尸进程
int GetProcessState(DWORD dwProcessID) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessID);

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		DWORD state = 1;//先置1，一旦有线程还在运行就置0
		THREADENTRY32 te = { sizeof(te) };
		BOOL fOk = Thread32First(hSnapshot, &te);
		for (; fOk; fOk = Thread32Next(hSnapshot, &te)) {
			if (te.th32OwnerProcessID == dwProcessID) {
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
				DWORD suspendCount = SuspendThread(hThread);//返回之前的挂起数，大于0表示已挂起
				ResumeThread(hThread);//马上恢复，这样不会对目标程序造成影响
				CloseHandle(hThread);
				if (suspendCount == 0) state = 0; //是个判断所有线程都挂起的好方法
			}
		}
		CloseHandle(hSnapshot);
		return state;
	}
	return -1;
}


// 通过进程名获取进程句柄
HANDLE GetProcessHandleByName(PCHAR processName)
{
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE processSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	Process32First(processSnap, &processEntry);
	do
	{
		USES_CONVERSION;
		if (strcmp(processName, W2A(processEntry.szExeFile)) == 0 && GetProcessState(processEntry.th32ProcessID) == 0)
		{
			CloseHandle(processSnap);
			return OpenProcess(PROCESS_ALL_ACCESS, FALSE, processEntry.th32ProcessID);
		}
	} while (Process32Next(processSnap, &processEntry));

	CloseHandle(processSnap);
	return (HANDLE)NULL;
}

// 根据进程名获取PID
DWORD64 GetProcessIDByName(LPCTSTR processName)
{
	DWORD64 processID = 0xFFFFFFFF;
	HANDLE snapshot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	Process32First(snapshot, &processEntry);
	do
	{
		if (!_tcsicmp(processName, (LPCTSTR)processEntry.szExeFile) && GetProcessState(processEntry.th32ProcessID) == 0)
		{
			processID = processEntry.th32ProcessID;
			break;
		}
	} while (Process32Next(snapshot, &processEntry));

	CloseHandle(snapshot);
	return processID;
}


// 获取进程内所有模块信息
std::vector<ModuleInfo> GetModuleInfoByProcessId(DWORD64 processID)
{
	MODULEENTRY32 moduleEntry;
	USES_CONVERSION;

	std::cout << processID << std::endl;

	std::vector<ModuleInfo> moduleInfos = {};

	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	HANDLE moduleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);

	if (moduleSnap == INVALID_HANDLE_VALUE)
	{
		return{};
	}

	BOOL hasMoreModules = Module32First(moduleSnap, &moduleEntry);
	TCHAR* modulePath = NULL;
	TCHAR* moduleName = NULL;
	DWORD64 moduleBase = NULL;

	while (hasMoreModules)
	{
		ModuleInfo moduleInfo;

		USES_CONVERSION;

		modulePath = moduleEntry.szExePath;
		moduleBase = (DWORD64)moduleEntry.modBaseAddr;
		moduleName = moduleEntry.szModule;

		wcscpy_s(moduleInfo.modulePath, modulePath);
		wcscpy_s(moduleInfo.moduleName, moduleName);
		moduleInfo.moduleBase = moduleBase;

		moduleInfos.push_back(moduleInfo);
		hasMoreModules = Module32Next(moduleSnap, &moduleEntry);
	}

	CloseHandle(moduleSnap);
	return moduleInfos;
}


// 读取硬盘PE文件数据
DWORD64 ReadPEFile(LPSTR filePath, LPVOID* fileBuffer)
{
	FILE* file = NULL;

	fopen_s(&file, filePath, "rb");
	if (file == NULL)
	{
		return 0;
	}
	else
	{
		fseek(file, 0, SEEK_END);
		long long fileSize = ftell(file);
		fseek(file, 0, SEEK_SET);

		LPVOID buffer = malloc(sizeof(char) * fileSize);
		if (buffer == NULL)
		{
			fclose(file);
			return 0;
		}
		size_t bytesRead = fread(buffer, sizeof(char), fileSize, file);
		if (!bytesRead)
		{
			free(buffer);
			fclose(file);
			return 0;
		}
		*fileBuffer = buffer;
		buffer = NULL;

		fclose(file);
		return fileSize;
	}
	return 0;
}

// 读取PE头信息
DWORD64 ParsePEHeaders(LPVOID fileBuffer)
{
	if (fileBuffer == NULL)
	{
		return 0;
	}

	if (*((PWORD)fileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		return 0;
	}

	dosHeader = (IMAGE_DOS_HEADER*)fileBuffer;

	if (*((PDWORD)((DWORD64)fileBuffer + dosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		return 0;
	}

	ntHeader = (IMAGE_NT_HEADERS*)((DWORD64)fileBuffer + dosHeader->e_lfanew);
	fileHeader = (IMAGE_FILE_HEADER*)((DWORD64)ntHeader + 4);
	optionalHeader = (IMAGE_OPTIONAL_HEADER64*)((DWORD64)fileHeader + IMAGE_SIZEOF_FILE_HEADER);
	sectionHeader = (IMAGE_SECTION_HEADER*)((DWORD64)optionalHeader + fileHeader->SizeOfOptionalHeader);
	return 1;
}

// 拉伸PE结构
DWORD64 ExpandPEImageBuffer(LPVOID fileBuffer, LPVOID* imageBuffer)
{
	if (!fileBuffer || !imageBuffer)
		return 0;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileBuffer;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)fileBuffer + dos->e_lfanew);

	DWORD imageSize = nt->OptionalHeader.SizeOfImage;

	BYTE* buffer = (BYTE*)malloc(imageSize);
	if (!buffer)
		return 0;

	memset(buffer, 0, imageSize);

	memcpy(buffer,
		fileBuffer,
		nt->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER section =
		IMAGE_FIRST_SECTION(nt);

	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		memcpy(buffer + section[i].VirtualAddress,
			(BYTE*)fileBuffer + section[i].PointerToRawData,
			section[i].SizeOfRawData);
	}

	*imageBuffer = buffer;
	return imageSize;
}


// 获取.text节信息（V2）
bool GetCodeSectionInfoV2(PeTextInfo* textInfo)
{
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++)
	{
		if (strncmp((const char*)section->Name, ".text", 5) == 0)
		{
			textInfo->virtualAddress = section->VirtualAddress;
			textInfo->pointerToRawData = section->PointerToRawData;
			textInfo->size = section->SizeOfRawData;
			return true;
		}
	}
	return false;
}


// 反汇编
std::vector<DisassemblyInfo> DisassembleCode(unsigned char* startOffset, int size)
{
	std::vector<DisassemblyInfo> disassemblyInfos = {};

	csh handle;
	cs_insn* insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
	{
		return{};
	}

	count = cs_disasm(handle, (unsigned char*)startOffset, size, 0x0, 0, &insn);

	if (count > 0)
	{
		DWORD index;

		for (index = 0; index < count; index++)
		{
			DisassemblyInfo disasmInfo;
			memset(&disasmInfo, 0, sizeof(DisassemblyInfo));

			for (int x = 0; x < insn[index].size; x++)
			{
				disasmInfo.opCode[x] = insn[index].bytes[x];
			}

			disasmInfo.address = insn[index].address; // 这里是相对偏移（从0开始）
			disasmInfo.opCodeSize = insn[index].size;

			strcpy_s(disasmInfo.opString, insn[index].mnemonic);
			strcat_s(disasmInfo.opString, " ");
			strcat_s(disasmInfo.opString, insn[index].op_str);

			disasmInfo.opStringSize = (int)strlen(disasmInfo.opString);

			disassemblyInfos.push_back(disasmInfo);
		}
		cs_free(insn, count);
	}
	else
	{
		cs_close(&handle);
		return{};
	}
	cs_close(&handle);
	return disassemblyInfos;
}


bool IsSystemModule(TCHAR* path) {
	USES_CONVERSION;
	std::wstring strPath = path;
	std::transform(strPath.begin(), strPath.end(), strPath.begin(), ::tolower);

	char sysDir[MAX_PATH];
	GetSystemDirectoryA(sysDir, MAX_PATH);
	std::wstring sysPath = A2W(sysDir);
	std::transform(sysPath.begin(), sysPath.end(), sysPath.begin(), ::tolower);

	return strPath.find(sysPath) == 0 || strPath.find(L"c:\\windows\\winsxs") == 0;
}


struct HookRecord
{
	DWORD64 address;              // 内存中的真实地址
	std::vector<BYTE> original;   // 原始字节
	std::vector<BYTE> hooked;     // 被修改后的字节
};

std::unordered_map<int, HookRecord> hookList;
int maxHooks = 0;

int main(int argc, char* argv[])//CE已存在的功能
{
	USES_CONVERSION;
	DWORD64 fileSize = 0;
	LPVOID fileBuffer = NULL;

	DWORD pid;
	vector<string>moduleNames = { "WS2_32.dll","Victim.exe","DxForm.exe" }; // 大小写敏感
	std::cout << "请输入进程ID: ";
	std::cin >> pid;

	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (processHandle == NULL) {
		std::cerr << "打开进程失败，错误码: " << GetLastError() << std::endl;
		return 1;
	}

	std::cout << "成功获取进程句柄: " << processHandle << std::endl;

	std::vector<ModuleInfo> moduleInfos = GetModuleInfoByProcessId(pid);

	printf("moduleSiz is %d\n", (int)moduleInfos.size());

	for (int i = 0; i < moduleInfos.size(); i++)
	{
		if (find(moduleNames.begin(), moduleNames.end(), W2A(moduleInfos[i].moduleName)) != moduleNames.end() ||
			!IsSystemModule(moduleInfos[i].modulePath)) {

			printf("[*] 模块基地址: 0x%I64X | 模块路径: %s \n", moduleInfos[i].moduleBase, W2A(moduleInfos[i].modulePath));

			fileSize = ReadPEFile(W2A(moduleInfos[i].modulePath), &fileBuffer);

			DWORD64 ref = ParsePEHeaders(fileBuffer);

			LPVOID imageBuffer = NULL;
			DWORD64 sizeOfImage = ExpandPEImageBuffer(fileBuffer, &imageBuffer);

			std::cout << "sizeOfImage: " << std::hex << sizeOfImage << std::endl;

			PeTextInfo textInfo;
			if (!GetCodeSectionInfoV2(&textInfo))
				continue;

			std::cout << ".text size: " << textInfo.size << std::endl;
			std::cout << "virtualAddress: " << textInfo.virtualAddress << std::endl;

			// 文件侧 .text
			unsigned char* fileTextBuffer = (unsigned char*)malloc(textInfo.size);
			memcpy(fileTextBuffer, (unsigned char*)((DWORD64)imageBuffer + textInfo.virtualAddress), textInfo.size);

			// 内存侧 .text
			unsigned char* memoryTextBuffer = (unsigned char*)malloc(textInfo.size);
			DWORD64 moduleBase = moduleInfos[i].moduleBase;

			ReadProcessMemory(processHandle, (LPVOID)(moduleBase + textInfo.virtualAddress), memoryTextBuffer, textInfo.size, NULL);

			// 反汇编
			std::vector<DisassemblyInfo> fileDisassembly = DisassembleCode(fileTextBuffer, textInfo.size);
			std::vector<DisassemblyInfo> memoryDisassembly = DisassembleCode(memoryTextBuffer, textInfo.size);

			// 先把内存侧的指令按 address 建索引，方便按偏移查找
			std::unordered_map<unsigned long long, size_t> memIndexByAddr;
			memIndexByAddr.reserve(memoryDisassembly.size());//提供内存反汇编总条数的表
			for (size_t i = 0; i < memoryDisassembly.size(); ++i)
			{
				memIndexByAddr[memoryDisassembly[i].address] = i;//key是每一条内存指令偏移
			}

			// 遍历“文件侧”的指令，以它的 address 为基准，在“内存侧”找同一 address 的指令
			for (size_t k = 0; k < fileDisassembly.size(); ++k)
			{
				auto& f = fileDisassembly[k];

				auto it = memIndexByAddr.find(f.address);
				if (it == memIndexByAddr.end())
				{
					// 这个偏移在内存反汇编里不存在（可能是解码差异/截断），先跳过
					continue;
				}

				auto& m = memoryDisassembly[it->second];

				// 这里的 f.address / m.address 是“相对 .text 起始的偏移”
				// 真实地址 = moduleBase + textInfo.virtualAddress + f.address
				if (f.opCodeSize == m.opCodeSize &&
					memcmp(f.opCode, m.opCode, f.opCodeSize) == 0)
				{
					continue; // 完全一致，跳过
				}

				DWORD64 realAddr = moduleBase + textInfo.virtualAddress + f.address;

				// FF E0 这种 jmp rax
				if (m.opCode[0] == 0xFF && m.opCode[1] == 0xE0)
				{
					printf("0x%I64X | ", realAddr);
					printf("文件汇编: %-45s | ", f.opString);
					printf("内存汇编: %-45s | ", m.opString);

					printf("文件=> ");
					for (int l = 0; l < f.opCodeSize; l++)
						printf("0x%02X ", f.opCode[l]);

					printf(" 内存=> ");
					for (int l = 0; l < m.opCodeSize; l++)
						printf("0x%02X ", m.opCode[l]);
					printf("\n");
				}

				// E9 rel32 jmp
				if (m.opCode[0] == 0xE9 && m.opCodeSize == 5)
				{
					int32_t offset = (int32_t)(
						(m.opCode[1]) |
						(m.opCode[2] << 8) |
						(m.opCode[3] << 16) |
						(m.opCode[4] << 24)
						);

					DWORD64 target = realAddr + offset + 5;
					if (target > moduleBase && target < moduleBase + sizeOfImage)
					{
						// 目标还在本模块内，可能是正常跳转，跳过
						continue;
					}

					printf("[%d] 发现Hook -> 0x%I64X\n", (int)hookList.size(), realAddr);

					printf("0x%I64X | ", realAddr);
					printf("文件汇编: %-45s | ", f.opString);
					printf("内存汇编: %-45s | ", m.opString);

					printf("文件=> ");
					for (int l = 0; l < f.opCodeSize; l++)
						printf("0x%02X ", f.opCode[l]);

					printf(" 内存=> ");
					for (int l = 0; l < m.opCodeSize; l++)
						printf("0x%02X ", m.opCode[l]);
					printf("\n");

					HookRecord rec;
					rec.address = realAddr;

					//for (int l = 0; l < f.opCodeSize; l++)
					//	rec.original.push_back(f.opCode[l]);

					//for (int l = 0; l < m.opCodeSize; l++)
					//	rec.hooked.push_back(m.opCode[l]);


					for (int l = 0; l < 5; l++) {//多恢复几行反汇编
						for (int m = 0; m < fileDisassembly[k + l].opCodeSize; m++)
							rec.original.push_back(fileDisassembly[k + l].opCode[m]);
					}

					hookList[maxHooks++] = rec;

				}
			}


			// 释放
			free(fileBuffer);
			free(fileTextBuffer);
			free(memoryTextBuffer);
			free(imageBuffer);
		}
	}

	if (!hookList.empty())
	{
	local_1:
		printf("\n发现 %d 个 Hook，可输入序号恢复：\n", (int)hookList.size());
		for (auto& item : hookList)
		{
			printf("[%d] 0x%I64X\n", item.first, item.second.address);
		}
		printf("请输入要恢复的序号（-1退出）：");
		int index = -1;
		std::cin >> index;

		if (index >= 0 && index < maxHooks)//不能用hookList.size()，有可能序号很多
		{
			DWORD oldProtect = 0;
			VirtualProtectEx(processHandle, (LPVOID)hookList[index].address,
				hookList[index].original.size(),
				PAGE_EXECUTE_READWRITE, &oldProtect);

			WriteProcessMemory(processHandle,
				(LPVOID)hookList[index].address,
				hookList[index].original.data(),
				hookList[index].original.size(),
				NULL);

			VirtualProtectEx(processHandle, (LPVOID)hookList[index].address,
				hookList[index].original.size(),
				oldProtect, &oldProtect);

			printf("序号 %d 的 Hook 已恢复！\n", index);

			hookList.erase(index);
		}
		if (!hookList.empty())
			goto local_1;
	}
	else
	{
		printf("未发现 Hook。\n");
	}

	CloseHandle(processHandle);
	system("pause");
	return 0;
}
