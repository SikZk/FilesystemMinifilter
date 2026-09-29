#pragma once
#include <ntifs.h>
#include <fltKernel.h>
#include "FsTelemetry.h"

#define MAX_LOG_COUNT 512
#define ENLISTED_IN_TRANSACTION 0x1

extern LIST_ENTRY LogList;
extern KSPIN_LOCK LogLock;
extern volatile LONG LogCount;

//
// Kernel-only list node. Only the FS_TELEMETRY part is copied to the service.
//

typedef struct _FS_LOG_ENTRY
{
    LIST_ENTRY   List;
    FS_TELEMETRY Telemetry;
} FS_LOG_ENTRY, * PFS_LOG_ENTRY;

NTSTATUS
SendLogs(
    _Out_writes_bytes_to_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
);
PFS_TELEMETRY CreateLog();

VOID FreeLogList();

VOID
FreeLog(
    _In_ PFS_TELEMETRY Log
);

VOID
InsertLog(
    _In_ PFS_TELEMETRY Log
);