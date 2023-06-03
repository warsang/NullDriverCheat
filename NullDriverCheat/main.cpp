#include "hook.h"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING reg_path) {
	UNREFERENCED_PARAMETER(driver_object);
	UNREFERENCED_PARAMETER(reg_path);

	if (hook::call_kernel_function(&hook::hook_handler)) {
		DbgPrint(0, 0, "NullDriver | Function hooked!\n");
		return STATUS_SUCCESS;
	}
	else {
		DbgPrint(0, 0, "NullDriver | Function hook failesd!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	


}