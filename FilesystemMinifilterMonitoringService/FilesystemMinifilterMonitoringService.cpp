#include "FilesystemMinifilterMonitoringService.h"
#include "EventLog.h"
#include "MinifilterCommunication.h"

CONST WCHAR* ServiceName = L"FilesystemMinifilterMonitoringService";
SERVICE_STATUS_HANDLE StatusHandle = 0;
SERVICE_STATUS        ServiceStatus = { 0 };
HANDLE                StopEvent = 0;

void  PerformCleanup() {
    DestroyFilterComms();
    DestroyEventLog();

    if (StopEvent != 0)
    {
        CloseHandle(StopEvent);
    }
}

void WINAPI ServiceControlHandler(DWORD dwControl) {
    if (dwControl == SERVICE_CONTROL_STOP || dwControl == SERVICE_CONTROL_SHUTDOWN) {
        ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        ServiceStatus.dwControlsAccepted = 0;
        ServiceStatus.dwWaitHint = 5000;
        SetServiceStatus(StatusHandle, &ServiceStatus);

        SetEvent(StopEvent);
    }
}

VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPWSTR* lpServiceArgVectors) {
    StatusHandle = RegisterServiceCtrlHandler(ServiceName, ServiceControlHandler);

    if (!StatusHandle) {
        return;
    }
    ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    ServiceStatus.dwWaitHint = 10000;

    SetServiceStatus(StatusHandle, &ServiceStatus);

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;

    do {
    
        BOOLEAN Result = InitializeEventLog();

        if (Result == FALSE) {
            break;
        }
        StopEvent = CreateEventW(0, TRUE, FALSE, 0);
        if (StopEvent == 0) {
            break;
        }

        Result = InitializeFilterComms();
        if (Result == FALSE) {
            break;
        }

        ServiceStatus.dwCurrentState = SERVICE_RUNNING;
        ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
        ServiceStatus.dwWaitHint = 0;

    } while (FALSE);

    SetServiceStatus(StatusHandle, &ServiceStatus);

    if (ServiceStatus.dwCurrentState != SERVICE_RUNNING) {
        PerformCleanup();
        return;
    }

    WaitForSingleObject(StopEvent, INFINITE);

    PerformCleanup();

    ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    ServiceStatus.dwControlsAccepted = 0;
    ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(StatusHandle, &ServiceStatus);
}

int wmain(int argc, WCHAR* argv[]) {
    SERVICE_TABLE_ENTRY DispatchTable[] =
    {
        { (PWCHAR)ServiceName, ServiceMain },
        { 0, 0 }
    };

    StartServiceCtrlDispatcher(DispatchTable);

    return 0;
}

