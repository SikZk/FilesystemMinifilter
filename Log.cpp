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
        ExFreePool2(Log, 'iniM', 0, 0);
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

        FreeLog((PFS_TELEMETRY)ListEntry);

        KeAcquireSpinLock(&LogLock, &OldIrql);
    }

    KeReleaseSpinLock(&LogLock, OldIrql);
}


NTSTATUS
SendLogs(
    _In_  PVOID  OutputBuffer,
    _In_  ULONG  OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    KIRQL    OldIrql = 0;
    ULONG    BytesWritten = 0;
    PUCHAR   Destination = (PUCHAR)OutputBuffer;
    ULONG    CopySize = sizeof(FS_TELEMETRY) - sizeof(LIST_ENTRY);

    KeAcquireSpinLock(&LogLock, &OldIrql);

    while (IsListEmpty(&LogList) == FALSE
        &&
        (SIZE_T)(OutputBufferSize - BytesWritten) >= sizeof(FS_TELEMETRY))
    {
        PFS_TELEMETRY Log = (PFS_TELEMETRY)RemoveHeadList(&LogList);

        RtlCopyMemory(Destination, (PUCHAR)Log + sizeof(LIST_ENTRY), CopySize);

        BytesWritten += CopySize;
        Destination += CopySize;

        FreeLog(Log);
    }

    KeReleaseSpinLock(&LogLock, OldIrql);

    *ReturnOutputBufferLength = BytesWritten;
    return STATUS_SUCCESS;
}

VOID
InsertLog(
    _In_ PFS_TELEMETRY Log
)
{
    KIRQL OldIrql;
    KeAcquireSpinLock(&LogLock, &OldIrql);
    InsertTailList(&LogList, &Log->List);
    KeReleaseSpinLock(&LogLock, OldIrql);
}

PFS_TELEMETRY
CreateLog()
{
    //
    // Reserve a slot. If we'd exceed the cap, give it back and drop
    //

    if (InterlockedIncrement(&LogCount) > MAX_LOG_COUNT)
    {
        InterlockedDecrement(&LogCount);
        return 0;
    }

    PFS_TELEMETRY Log = (PFS_TELEMETRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FS_TELEMETRY), 'iniM');

    if (Log == 0)
    {
        InterlockedDecrement(&LogCount);
    }

    return Log;
}
