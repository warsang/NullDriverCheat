#pragma once

#include <ntdef.h>

#define DebugMessage(x, ...) DbgPrintEx(0, 0, x, __VA_ARGS__)