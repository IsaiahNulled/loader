#pragma once
#include "definitions.h"
#include "memory.h"
#include "shared.h"

namespace Hook {
    BOOL Install(void* handlerAddr);
    NTSTATUS Handler(PVOID callParam);
}
