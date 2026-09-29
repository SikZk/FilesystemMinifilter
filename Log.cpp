#include "Log.h"

LIST_ENTRY LogList;
KSPIN_LOCK LogLock;

volatile LONG LogCount = 0;
VOID
FreeLog(
    _In_ PFS_TELEMETRY Log
)
{
    if (Log != NULL)
    {
        ExFreePool2(CONTAINING_RECORD(Log, FS_LOG_ENTRY, Telemetry), 'iniM', 0, 0);
        InterlockedDecrement(&LogCount);
    }
}

VOID
FreeLogList()
{
    PLIST_ENTRY   ListEntry;
    KIRQL         OldIrql;

    KeAcquireSpinLock(&LogLock, &OldIrql);

    while (IsListEmpty(&LogList) == FALSE)
    {
        ListEntry = RemoveHeadList(&LogList);
        KeReleaseSpinLock(&LogLock, OldIrql);

        FreeLog(&CONTAINING_RECORD(ListEntry, FS_LOG_ENTRY, List)->Telemetry);

        KeAcquireSpinLock(&LogLock, &OldIrql);
    }

    KeReleaseSpinLock(&LogLock, OldIrql);
}


NTSTATUS
SendLogs(
    _Out_writes_bytes_to_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    KIRQL    OldIrql = 0;
    ULONG    BytesWritten = 0;
    PUCHAR   Destination = (PUCHAR)OutputBuffer;
    NTSTATUS Status = STATUS_SUCCESS;

    while (OutputBufferSize - BytesWritten >= sizeof(FS_TELEMETRY))
    {
        KeAcquireSpinLock(&LogLock, &OldIrql);

        if (IsListEmpty(&LogList))
        {
            KeReleaseSpinLock(&LogLock, OldIrql);
            break;
        }

        PFS_LOG_ENTRY Entry = CONTAINING_RECORD(RemoveHeadList(&LogList), FS_LOG_ENTRY, List);

        KeReleaseSpinLock(&LogLock, OldIrql);

        __try
        {
            RtlCopyMemory(Destination, &Entry->Telemetry, sizeof(FS_TELEMETRY));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            KeAcquireSpinLock(&LogLock, &OldIrql);
            InsertHeadList(&LogList, &Entry->List);
            KeReleaseSpinLock(&LogLock, OldIrql);

            Status = GetExceptionCode();
            break;
        }

        BytesWritten += sizeof(FS_TELEMETRY);
        Destination += sizeof(FS_TELEMETRY);

        FreeLog(&Entry->Telemetry);
    }

    *ReturnOutputBufferLength = BytesWritten;
    return Status;
}

VOID
InsertLog(
    _In_ PFS_TELEMETRY Log
)
{
    KIRQL OldIrql;
    KeAcquireSpinLock(&LogLock, &OldIrql);
    InsertTailList(&LogList, &CONTAINING_RECORD(Log, FS_LOG_ENTRY, Telemetry)->List);
    KeReleaseSpinLock(&LogLock, OldIrql);
}

PFS_TELEMETRY
CreateLog()
{

    if (InterlockedIncrement(&LogCount) > MAX_LOG_COUNT)
    {
        InterlockedDecrement(&LogCount);
        return 0;
    }

    PFS_LOG_ENTRY Entry = (PFS_LOG_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FS_LOG_ENTRY), 'iniM');

    if (Entry == 0)
    {
        InterlockedDecrement(&LogCount);
        return 0;
    }

    return &Entry->Telemetry;
}
