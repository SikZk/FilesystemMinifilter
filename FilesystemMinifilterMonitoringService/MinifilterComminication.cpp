#include "MinifilterCommunication.h"
#include "FilesystemMinifilterMonitoringService.h"
#include "EventLog.h"

#pragma comment(lib, "FltLib.lib")

#define LOG_BUFFER_COUNT  10
#define LOG_BUFFER_SIZE   (sizeof(FS_TELEMETRY) * LOG_BUFFER_COUNT)

UCHAR  Buffer[LOG_BUFFER_SIZE];
HANDLE WorkerThreadHandle = 0;

ULONG WINAPI WorkerThread(_In_ HANDLE FilterPort)
{
    ULONG BytesReturned = 0;
    ULONG Input = 0;

    while (WaitForSingleObject(StopEvent, 100) == WAIT_TIMEOUT)
    {
        HRESULT Result = FilterSendMessage(
            FilterPort,
            &Input,
            sizeof(Input),
            Buffer,
            sizeof(Buffer),
            &BytesReturned
        );

        if (IS_ERROR(Result))
        {
            break;
        }

        if (BytesReturned == 0)
        {
            continue;
        }


        ULONG Offset = 0;

        while (Offset + sizeof(FS_TELEMETRY) <= BytesReturned)
        {
            PFS_TELEMETRY Log = (PFS_TELEMETRY)(Buffer + Offset);

            LogFsTelemetry(Log);

            Offset += sizeof(FS_TELEMETRY);
        }
    }

    CloseHandle(FilterPort);
    return 0;
}

BOOLEAN InitializeFilterComms() {
	HANDLE  FilterPort;
	HRESULT Result = FilterConnectCommunicationPort(L"\\FilesystemMinifilter", 0, 0, 0, 0, &FilterPort);

	if (IS_ERROR(Result))
	{
		return FALSE;
	}

	WorkerThreadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)WorkerThread, FilterPort, 0, 0);

	if (WorkerThreadHandle == 0)
	{
		CloseHandle(FilterPort);
		return FALSE;
	}

	return TRUE;
}

void DestroyFilterComms() {

	if (WorkerThreadHandle != 0)
	{
		WaitForSingleObject(WorkerThreadHandle, INFINITE);
		CloseHandle(WorkerThreadHandle);
		WorkerThreadHandle = 0;
	}
}