#include "FilesystemMinifilter.h"
#include "Callbacks.h"
#include "Log.h"

PFLT_FILTER Filter;
PFLT_PORT FilterPort;
UNICODE_STRING FilterName = RTL_CONSTANT_STRING(L"\\FilesystemMinifilter");
PFLT_PORT ClientPort = 0;

CONST FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_TRANSACTION_CONTEXT,
      0,
      0,
      sizeof(TRANSACTION_CONTEXT),
      'iniM' },

    { FLT_CONTEXT_END }
};

CONST FLT_OPERATION_REGISTRATION Callbacks[] =
{
    { IRP_MJ_CREATE,                               0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_CREATE_NAMED_PIPE,                    0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_WRITE,                                FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_SET_INFORMATION,                      0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_DIRECTORY_CONTROL,                    0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,  0, PreOperationCallback, PostOperationCallback },
    { IRP_MJ_CLEANUP,                              0, PreOperationCallback, 0 },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),               //  Size
    FLT_REGISTRATION_VERSION,               //  Version
    FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS,   //  Flags
    ContextRegistration,                    //  Context
    Callbacks,                              //  The callbacks (pre-op or post-op) for each type of I/O we want to filter
    FilterUnload,                           //  Unload callback
    0,                                      //  InstanceSetup
    0,                                      //  InstanceQueryTeardown
    0,                                      //  InstanceTeardownStart
    0,                                      //  InstanceTeardownComplete
    0,                                      //  GenerateFileName
    0,                                      //  NormalizeNameComponentCallback
    0,                                      //  NormalizeContextCleanupCallback
    TransactionCallback,                    //  TransactionNotificationCallback
    0,                                      //  NormalizeNameComponentExCallback
    0                                       //  SectionNotificationCallback
};

VOID PortClientDisconnect(_In_opt_ PVOID ConnectionCookie) {
    UNREFERENCED_PARAMETER(ConnectionCookie);

    KdPrint(("[FilesystemMinifilter] Service disconnected"));

    FltCloseClientPort(Filter, &ClientPort);
}

NTSTATUS PortClientMessage(
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
) {
    UNREFERENCED_PARAMETER(ConnectionCookie);
    UNREFERENCED_PARAMETER(InputBufferSize);
    UNREFERENCED_PARAMETER(InputBuffer);

    KdPrint(("[FilesystemMinifilter] Service sent read request"));
    if (OutputBuffer == 0 || OutputBufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    return SendLogs(OutputBuffer, OutputBufferSize, ReturnOutputBufferLength);
}

NTSTATUS PortClientConnect(
    _In_ PFLT_PORT _ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
) {
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    ClientPort = _ClientPort;
    KdPrint(("[FilesystemMinifilter] Client connected"));
    return STATUS_SUCCESS;
}

NTSTATUS CreateFilterPort() {
    OBJECT_ATTRIBUTES    FilterAttributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    NTSTATUS Status = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);
    
    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Mini] Could not create port SD: 0x%08lX", Status));
        return Status;
    }

    InitializeObjectAttributes(
        &FilterAttributes,
        &FilterName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        0,
        SecurityDescriptor
    );

    Status = FltCreateCommunicationPort(
        Filter,
        &FilterPort,
        &FilterAttributes,
        0,
        PortClientConnect,
        PortClientDisconnect,
        PortClientMessage,
        1
    );

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Mini] Could not create comms port: 0x%08lX", Status));
    }

    FltFreeSecurityDescriptor(SecurityDescriptor);
    return Status;
}

EXTERN_C NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    InitializeListHead(&LogList);
	KeInitializeSpinLock(&LogLock);

    NTSTATUS Status = FltRegisterFilter(DriverObject, &FilterRegistration, &Filter);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Mini] Could not register filter: 0x%08lX", Status));
        return Status;
    }

    Status = CreateFilterPort();

    if (!NT_SUCCESS(Status)) {
        FltUnregisterFilter(Filter);
        return Status;
    }


    Status = FltStartFiltering(Filter);

    if (!NT_SUCCESS(Status)) {
        KdPrint(("[Mini] Could not start filtering: 0x%08lX", Status));
        FltCloseCommunicationPort(FilterPort);
        FltUnregisterFilter(Filter);
    }

    return Status;

}

NTSTATUS
FilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    FltCloseCommunicationPort(FilterPort);
    FltUnregisterFilter(Filter);
    FreeLogList();

    KdPrint(("[Mini] Unloaded"));
    return STATUS_SUCCESS;
}