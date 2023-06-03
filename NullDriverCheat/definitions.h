#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <ntstrsafe.h>
#include <wdm.h>
#pragma comment (lib,"ntoskrnl.lib")

typedef enum _SYSTEM_INFORMATION_CLASS
{

	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11

} SYSTEM_INFORMATION_CLASS,
* PSYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];

} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];

}RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

extern "C" __declspec(dllimport)
NTSTATUS NTAPI ZwProtectVirtualMemory(HANDLE ProcessHandle,
	PVOID * BaseAddress,
	SIZE_T * NumberOfBytesToProtect,
	ULONG  NewAccessProtection,
	PULONG OldAccessProtection
);

extern "C" NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID ImageBase,
	_In_ PCCH RoutineName
);

extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

extern "C" NTKERNELAPI
PPEB
PsGetProcessPeb(
	IN PEPROCESS Process
);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS  	SourceProcess,
	PVOID  	SourceAddress,
	PEPROCESS  	TargetProcess,
	PVOID  	TargetAddress,
	SIZE_T  	BufferSize,
	KPROCESSOR_MODE  	PreviousMode,
	PSIZE_T  	ReturnSize
);

typedef VOID(NTAPI* PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16]; // size = 16
	PVOID Reserved2[10];// 10 * 8 = 80
	UNICODE_STRING ImagePathName; //hex(80) = 0x60
	UNICODE_STRING CommandLine; //0x70
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


//Structs from https://www.vergiliusproject.com/kernels/x64/Windows%2011/Insider%20Preview%20(Jun%202021)/_PEB

typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                                           //0x0
	UCHAR Initialized;                                                      //0x4
	VOID* SsHandle;                                                         //0x8
	struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
	struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
	struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30

}PEB_LDR_DATA, * PPEB_LDR_DATA;;

typedef struct _LDR_DATA_TABLE_ENTRY {
	struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
	struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
	struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
	VOID* DllBase;                                                          //0x30
	VOID* EntryPoint;                                                       //0x38
	ULONG SizeOfImage;                                                      //0x40
	struct _UNICODE_STRING FullDllName;                                     //0x48
	struct _UNICODE_STRING BaseDllName;                                     //0x58
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Padding1[2];
    BYTE BeingDebugged; //0x2
    BYTE Padding2[16];
    PPEB_LDR_DATA Ldr;//0x18
} PEB, * PPEB;


//char(*__kaboom)[sizeof(PEB)] = 1;
//static_assert(sizeof(PEB) == 0x284, "Player class size");