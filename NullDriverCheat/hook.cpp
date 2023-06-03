#include "hook.h"
#include "messages.h"


GdiSelectBrush_t GdiSelectBrush = NULL;
PatBlt_t NtGdiPatBlt = NULL;
NtUserGetDC_t NtUserGetDC = NULL;
NtGdiCreateSolidBrush_t NtGdiCreateSolidBrush = NULL;
ReleaseDC_t NtUserReleaseDC = NULL;
DeleteObjectApp_t NtGdiDeleObjectApp = NULL;


bool hook::call_kernel_function(void* kernel_function_address) 
{

	if (!kernel_function_address) {
		return false;
	}

	PVOID* function = reinterpret_cast<PVOID*>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", 
		"NtOpenCompositionSurfaceSectionInfo"));
		//Mine -> "NtOpenCompositionSurfaceSectionInfo"

	if (!function) {
		return false;
	}

	BYTE orig[] = { 0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; // Allocated memory where we will write our shellcode;
	//sizeof(orig) == sizeof(shell_code) + sizeof(&hook_address)
	BYTE shell_code[] = {0x90,0x90,0x90,0x48,0xB8};
	//nop nop ; Used to bypass basic anti-hooks
	//mov rax, fffff
	BYTE shell_code_end[] = { 0xFF,0xE0 }; //jmp rax

	RtlSecureZeroMemory(&orig, sizeof(orig));
	memcpy((PVOID)(ULONG_PTR)orig,&shell_code,sizeof(shell_code));
	uintptr_t hook_address = reinterpret_cast<uintptr_t>(kernel_function_address);
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code)), &hook_address, sizeof(void*));
	memcpy((PVOID)((ULONG_PTR)orig + sizeof(shell_code) + sizeof(void*)), &shell_code_end, sizeof(shell_code_end));


	write_to_read_only_memory(function, &orig, sizeof(orig));

	//Draw rectangle stuff from https://www.youtube.com/watch?v=YzY-Uhg7IUU
	/*
	GdiSelectBrush = (GdiSelectBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiSelectBrush");
	NtGdiCreateSolidBrush = (NtGdiCreateSolidBrush_t)get_system_module_export(L"win32kfull.sys", "NtGdiCreateSolidBrush");
	NtGdiPatBlt = (PatBlt_t)get_system_module_export(L"win32kfull.sys", "NtGdiPatBlt");
	NtUserGetDC = (NtUserGetDC_t)get_system_module_export(L"win32kfull.sys", "NtUserGetDC");
	NtUserReleaseDC = (ReleaseDC_t)get_system_module_export(L"win32kfull.sys", "NtUserReleaseDC");
	NtGdiDeleObjectApp = (DeleteObjectApp_t)get_system_module_export(L"win32kfull.sys", "NtGdiDeleObjectApp");
	*/


	return true;
}

NTSTATUS hook::hook_handler(PVOID  called_param) {

	NULL_MEMORY* instructions = (NULL_MEMORY*)called_param;
	DebugMessage("Command received");

	//Getting module base address
	if (instructions->req_base != FALSE) {
		DebugMessage("Hi from Kernel");
		ANSI_STRING AS;
		UNICODE_STRING ModuleName;

		RtlInitAnsiString(&AS, instructions->module_name);
		RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);

		PEPROCESS process;
		DebugMessage("My process id is: %lu", instructions->pid);
		PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
		if (process) {
			ULONG64 base_address64 = NULL;
			base_address64 = get_module_base_x64(process, ModuleName);
			instructions->base_address = base_address64;
			RtlFreeUnicodeString(&ModuleName);
		}
		else {
			return STATUS_ABANDONED;
		}
	}

	//Writting memory
	else if (instructions->write != FALSE) {
		//Check that we're in a valid memory range
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0) {

			//We allocate a buffer
			PVOID kernelBuff = ExAllocatePool(NonPagedPool, instructions->size);

			if (!kernelBuff)
			{
				// couldn't allocate mem buffer
				return STATUS_UNSUCCESSFUL;
			}

			if (!memcpy(kernelBuff, instructions->buffer_address, instructions->size)) {
				return STATUS_UNSUCCESSFUL;
			}

			PEPROCESS process;
			PsLookupProcessByProcessId((HANDLE)instructions->pid, &process);
			write_kernel_memory((HANDLE)instructions->pid, instructions->address, kernelBuff, instructions->size);
			ExFreePool(kernelBuff);

		}
	}

	else if (instructions->read != FALSE) {
		DebugMessage("Read command received");
		//Check that we're in a valid memory range
		if (instructions->address < 0x7FFFFFFFFFFF && instructions->address > 0) {
			DebugMessage("address is in the right thing");
			DebugMessage("PID: %d",instructions->pid);
			DebugMessage("address: %d", instructions->address);
			DebugMessage("Size: %d", instructions->size);




			read_kernel_memory((HANDLE)instructions->pid, (uintptr_t)instructions->address, instructions->output, instructions->size);
			DebugMessage("outpu: %d", *(DWORD*)instructions->output);

		}
	}

	return STATUS_SUCCESS;
}


INT hook::FrameRect(HDC hDC, CONST RECT* lprc, HBRUSH hbr, int thickness) {
	HBRUSH oldbrush;
	RECT r = *lprc;

	if (!(oldbrush = GdiSelectBrush(hDC, hbr))) return 0;

	NtGdiPatBlt(hDC, r.left, r.top, thickness, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.right - thickness, r.top, thickness, r.bottom - r.top, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.top, r.right, thickness, PATCOPY);
	NtGdiPatBlt(hDC, r.left, r.bottom - thickness, r.right, r.right - r.left, PATCOPY);
	
	GdiSelectBrush(hDC, oldbrush);
	return 1;

};
