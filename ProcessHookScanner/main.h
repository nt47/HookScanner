#pragma once
#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <iostream>
#include <atlconv.h>
#include <vector>
#include <inttypes.h>
#include<algorithm>
#include <unordered_map>

#include <capstone/capstone.h>//capstone-6.0.0-Alpha1

using namespace std;

// 存放PE信息段
struct PeTextInfo
{
	DWORD64 virtualAddress;    // 节区在内存的偏移
	DWORD64 pointerToRawData;  // 节区在文件中的偏移
	DWORD64 size;              // 大小
};

// 存放进程内所有模块信息
typedef struct
{
	TCHAR modulePath[256];      // 模块路径
	TCHAR moduleName[128];      // 模块名
	long long moduleBase;      // 模块基址
}ModuleInfo;

// 存放反汇编数据
typedef struct
{
	int opCodeSize;            // 机器码长度
	int opStringSize;          // 反汇编长度
	unsigned long long address;// 相对地址
	unsigned char opCode[16];  // 机器码
	char opString[256];        // 反汇编
}DisassemblyInfo;

// 全局PE结构
IMAGE_DOS_HEADER* dosHeader;              // DOS头
IMAGE_NT_HEADERS* ntHeader;               // NT头
IMAGE_FILE_HEADER* fileHeader;            // 标准PE头
IMAGE_OPTIONAL_HEADER64* optionalHeader;  // 可选PE头
IMAGE_SECTION_HEADER* sectionHeader;      // 节表