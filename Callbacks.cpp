#include <initguid.h>   // must come before ntifs.h so GUID_ECP_* get defined here, not just declared
#include "Callbacks.h"
#include "Log.h"
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ntstrsafe.h>

CONST UNICODE_STRING ProtectedDir = RTL_CONSTANT_STRING(L"\\Program Files\\FilesystemMinifilter\\");

VOID
FormatSocketAddress(
    _In_ PSOCKADDR_STORAGE_NFS Address,
    _Out_writes_(BufferLen) PWCHAR Buffer,
    _In_ SIZE_T BufferLen,
    _Out_ PUSHORT Port
)
{
    PSOCKADDR_STORAGE Storage = (PSOCKADDR_STORAGE)Address;

    *Port = 0;

    if (Storage->ss_family == AF_INET)
    {
        PSOCKADDR_IN Addr4 = (PSOCKADDR_IN)Storage;
        PUCHAR b = (PUCHAR)&Addr4->sin_addr;

        RtlStringCchPrintfW(
            Buffer, BufferLen,
            L"%u.%u.%u.%u",
            b[0], b[1], b[2], b[3]
        );

        *Port = RtlUshortByteSwap(Addr4->sin_port);
    }
    else if (Storage->ss_family == AF_INET6)
    {
        PSOCKADDR_IN6 Addr6 = (PSOCKADDR_IN6)Storage;
        PUCHAR b = (PUCHAR)&Addr6->sin6_addr;

        RtlStringCchPrintfW(
            Buffer, BufferLen,
            L"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        );

        *Port = RtlUshortByteSwap(Addr6->sin6_port);
    }
}

VOID
CopyUnicodeStringToBuffer(
    _In_ PUNICODE_STRING Source,
    _Out_writes_(BufferLen) PWCHAR Buffer,
    _In_ SIZE_T BufferLen
)
{
    if (Source == 0 || Source->Buffer == 0 || Source->Length == 0)
    {
        return;
    }

    ULONG CopyLen = min(
        Source->Length,
        (ULONG)(BufferLen - 1) * sizeof(WCHAR)
    );

    RtlCopyMemory(Buffer, Source->Buffer, CopyLen);
    Buffer[CopyLen / sizeof(WCHAR)] = L'\0';
}

BOOLEAN
UnicodeStringContains(
    _In_ PCUNICODE_STRING Haystack,
    _In_ PCUNICODE_STRING Needle
)
{
    if (Needle->Length == 0 || Haystack->Length < Needle->Length)
    {
        return FALSE;
    }

    ULONG NeedleChars = Needle->Length / sizeof(WCHAR);
    ULONG HaystackChars = Haystack->Length / sizeof(WCHAR);
    ULONG LastStart = HaystackChars - NeedleChars;

    for (ULONG i = 0; i <= LastStart; i++)
    {
        BOOLEAN Match = TRUE;

        for (ULONG j = 0; j < NeedleChars; j++)
        {
            if (RtlUpcaseUnicodeChar(Haystack->Buffer[i + j]) !=
                RtlUpcaseUnicodeChar(Needle->Buffer[j]))
            {
                Match = FALSE;
                break;
            }
        }

        if (Match)
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN
IsDangerousCreate(
    _In_ PFLT_CALLBACK_DATA Data
)
{
    ACCESS_MASK DesiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;

    return (DesiredAccess & ~SAFE_ACCESS_MASK) != 0;
}


BOOLEAN
IsTamperingAttempt(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo
) {
    if (PsIsProtectedProcess(PsGetCurrentProcess())) {
        return FALSE;
    }

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return FALSE;
    }

    if (!UnicodeStringContains(&NameInfo->Name, &ProtectedDir)) {
        return FALSE;
    }

    return IsDangerousCreate(Data);
}

VOID
ParseEcp(
    _In_ PFLT_FILTER       Filter,
    _In_ PFLT_CALLBACK_DATA Data,
    _Inout_ PFS_TELEMETRY   Log
) {
    PECP_LIST EcpList = 0;
    NTSTATUS  Status;

    Status = FltGetEcpListFromCallbackData(Filter, Data, &EcpList);

    if (!NT_SUCCESS(Status) || EcpList == 0) {
        return;
    }

    PSRV_OPEN_ECP_CONTEXT SrvOpen = 0;

    Status = FltFindExtraCreateParameter(
        Filter,
        EcpList,
        &GUID_ECP_SRV_OPEN,
        (PVOID*)&SrvOpen,
        0
    );

    if (NT_SUCCESS(Status) && SrvOpen != 0) {
        Log->OpData.Enrichment.Create.IsRemoteOpen = TRUE;
        Log->OpData.Enrichment.Create.EcpCount++;

        CopyUnicodeStringToBuffer(
            SrvOpen->ShareName,
            Log->OpData.Enrichment.Create.ShareName,
            ARRAYSIZE(Log->OpData.Enrichment.Create.ShareName)
        );

        if (SrvOpen->SocketAddress != 0)
        {
            FormatSocketAddress(
                SrvOpen->SocketAddress,
                Log->OpData.Enrichment.Create.RemoteAddress,
                ARRAYSIZE(Log->OpData.Enrichment.Create.RemoteAddress),
                &Log->OpData.Enrichment.Create.RemotePort
            );
        }
    }

    PNFS_OPEN_ECP_CONTEXT NfsOpen = 0;

    Status = FltFindExtraCreateParameter(
        Filter,
        EcpList,
        &GUID_ECP_NFS_OPEN,
        (PVOID*)&NfsOpen,
        0
    );

    if (NT_SUCCESS(Status) && NfsOpen != 0) {
        Log->OpData.Enrichment.Create.IsRemoteOpen = TRUE;
        Log->OpData.Enrichment.Create.EcpCount++;

        if (Log->OpData.Enrichment.Create.ShareName[0] == L'\0')
        {
            CopyUnicodeStringToBuffer(
                NfsOpen->ExportAlias,
                Log->OpData.Enrichment.Create.ShareName,
                ARRAYSIZE(Log->OpData.Enrichment.Create.ShareName)
            );
        }

        if (Log->OpData.Enrichment.Create.RemoteAddress[0] == L'\0' &&
            NfsOpen->ClientSocketAddress != 0)
        {
            FormatSocketAddress(
                NfsOpen->ClientSocketAddress,
                Log->OpData.Enrichment.Create.RemoteAddress,
                ARRAYSIZE(Log->OpData.Enrichment.Create.RemoteAddress),
                &Log->OpData.Enrichment.Create.RemotePort
            );
        }
    }
    PNETWORK_OPEN_ECP_CONTEXT NetOpen = 0;

    Status = FltFindExtraCreateParameter(
        Filter,
        EcpList,
        &GUID_ECP_NETWORK_OPEN_CONTEXT,
        (PVOID*)&NetOpen,
        0
    );

    if (NT_SUCCESS(Status) && NetOpen != 0)
    {
        Log->OpData.Enrichment.Create.EcpCount++;
        Log->OpData.Enrichment.Create.NetworkLocation = NetOpen->in.Location;

        if (NetOpen->in.Location == NetworkOpenLocationRemote)
        {
            Log->OpData.Enrichment.Create.IsRemoteOpen = TRUE;
        }
    }
}

VOID
SetLogPreOperationData(
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PFS_TELEMETRY Log
) {
    KeQuerySystemTime(&Log->OriginatingTime);
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS       Status = FltGetDeviceObject(FltObjects->Volume, &DeviceObject);

    if (NT_SUCCESS(Status)) {
        ObDereferenceObject(DeviceObject);
    }
    else {
        DeviceObject = 0;
    }

    PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;

    Log->MajorFunction = Iopb->MajorFunction;
    Log->MinorFunction = Iopb->MinorFunction;
    Log->IrpFlags = Iopb->IrpFlags;
    Log->Flags = Data->Flags;
    Log->DeviceObject = (SIZE_T)DeviceObject;
    Log->FileObject = (SIZE_T)FltObjects->FileObject;
    Log->Transaction = (SIZE_T)FltObjects->Transaction;
    Log->ProcessId = PsGetCurrentProcessId();
    Log->ThreadId = PsGetCurrentThreadId();

    switch (Iopb->MajorFunction) {
        case IRP_MJ_CREATE: {
            ParseEcp(FltObjects->Filter, Data, Log);
            break;
        }
        case IRP_MJ_SET_INFORMATION: {
            FILE_INFORMATION_CLASS InfoClass = Iopb->Parameters.SetFileInformation.FileInformationClass;
            PVOID                  InfoBuffer = Iopb->Parameters.SetFileInformation.InfoBuffer;

            Log->OpData.Enrichment.SetInformation.InfoClass = InfoClass;

            switch (InfoClass) {
                case FileRenameInformation: {
                    PFILE_RENAME_INFORMATION Info = (PFILE_RENAME_INFORMATION)InfoBuffer;

                    Log->OpData.Enrichment.SetInformation.Rename.ReplaceIfExists =
                        Info->ReplaceIfExists;

                    ULONG CopyLen = min(
                        Info->FileNameLength,
                        (ARRAYSIZE(Log->OpData.Enrichment.SetInformation.Rename.TargetFileName) - 1)
                        * sizeof(WCHAR)
                    );

                    RtlCopyMemory(
                        Log->OpData.Enrichment.SetInformation.Rename.TargetFileName,
                        Info->FileName,
                        CopyLen
                    );

                    Log->OpData.Enrichment.SetInformation.Rename.TargetFileName[
                        CopyLen / sizeof(WCHAR)] = L'\0';
                    break;
                }
                case FileRenameInformationEx: {

                    PFILE_RENAME_INFORMATION Info = (PFILE_RENAME_INFORMATION)InfoBuffer;

                    Log->OpData.Enrichment.SetInformation.Rename.ReplaceIfExists =
                        (Info->Flags & FILE_RENAME_REPLACE_IF_EXISTS) != 0;

                    ULONG CopyLen = min(
                        Info->FileNameLength,
                        (ARRAYSIZE(Log->OpData.Enrichment.SetInformation.Rename.TargetFileName) - 1) * sizeof(WCHAR)
                    );

                    RtlCopyMemory(
                        Log->OpData.Enrichment.SetInformation.Rename.TargetFileName,
                        Info->FileName,
                        CopyLen
                    );

                    Log->OpData.Enrichment.SetInformation.Rename.TargetFileName[CopyLen / sizeof(WCHAR)] = L'\0';
                    break;
                }
                case FileDispositionInformation: {
                    PFILE_DISPOSITION_INFORMATION Info = (PFILE_DISPOSITION_INFORMATION)InfoBuffer;

                    Log->OpData.Enrichment.SetInformation.Disposition.DeleteFile =
                        Info->DeleteFile;
                    break;
                }

                case FileDispositionInformationEx: {
                    PFILE_DISPOSITION_INFORMATION_EX Info = (PFILE_DISPOSITION_INFORMATION_EX)InfoBuffer;

                    Log->OpData.Enrichment.SetInformation.Disposition.DeleteFile =
                        (Info->Flags & FILE_DISPOSITION_FLAG_DELETE) != 0;
                    break;
                }
                case FileBasicInformation: {
                    PFILE_BASIC_INFORMATION Info = (PFILE_BASIC_INFORMATION)InfoBuffer;

                    Log->OpData.Enrichment.SetInformation.Basic.CreationTime = Info->CreationTime;
                    Log->OpData.Enrichment.SetInformation.Basic.LastWriteTime = Info->LastWriteTime;
                    Log->OpData.Enrichment.SetInformation.Basic.FileAttributes = Info->FileAttributes;
                    break;
                }

                default: {
                    break;
                }
            }
            break;
        }
        default: {
            break;
        }
    }
}

FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    FLT_PREOP_CALLBACK_STATUS CallbackStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (
        Data->RequestorMode == KernelMode &&
        IoGetCurrentProcess() == PsInitialSystemProcess
    ) {
        return CallbackStatus;
    }
    PFLT_FILE_NAME_INFORMATION NameInformation = 0;

    if (FltObjects->FileObject != 0)
    {
        NTSTATUS Status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &NameInformation
        );

        if (!NT_SUCCESS(Status))
        {
            FltGetFileNameInformation(
                Data,
                FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
                &NameInformation
            );
        }

        if (NameInformation != 0 && IsTamperingAttempt(Data, NameInformation))
        {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            CallbackStatus = FLT_PREOP_COMPLETE;
        }
    }

    PFS_TELEMETRY Log = CreateLog();

    if (Log == 0) {
        if (NameInformation != 0)
        {
            FltReleaseFileNameInformation(NameInformation);
        }

        return CallbackStatus;
    }

    if (NameInformation != 0) {
        ULONG CopyLength = NameInformation->Name.Length;

        if (CopyLength > sizeof(Log->FileName) - sizeof(WCHAR))
        {
            CopyLength = sizeof(Log->FileName) - sizeof(WCHAR);
        }

        RtlCopyMemory(Log->FileName, NameInformation->Name.Buffer, CopyLength);
        Log->FileName[CopyLength / sizeof(WCHAR)] = L'\0';

        FltReleaseFileNameInformation(NameInformation);
    }

    SetLogPreOperationData(Data, FltObjects, Log);

    if (CallbackStatus == FLT_PREOP_COMPLETE) {
        PostOperationCallback(Data, FltObjects, Log, 0);
    }
    else {
        *CompletionContext = Log;
        CallbackStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    return CallbackStatus;
}

NTSTATUS
EnlistInTransaction(
    _In_ PCFLT_RELATED_OBJECTS FltObjects
) {
    PTRANSACTION_CONTEXT TransactionContext = 0;
    PTRANSACTION_CONTEXT OldTransactionContext = 0;

    NTSTATUS Status = FltGetTransactionContext(FltObjects->Instance, FltObjects->Transaction, (PFLT_CONTEXT*)&TransactionContext);


    if (NT_SUCCESS(Status))
    {
        if (FlagOn(TransactionContext->Flags, ENLISTED_IN_TRANSACTION))
        {

            FltReleaseContext(TransactionContext);
            return Status;
        }

        goto ENLIST_IN_TRANSACTION;
    }
    if (Status != STATUS_NOT_FOUND)
    {
        return Status;
    }

    Status = FltAllocateContext(FltObjects->Filter, FLT_TRANSACTION_CONTEXT, sizeof(TRANSACTION_CONTEXT), PagedPool, (PFLT_CONTEXT*)&TransactionContext);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    TransactionContext->Flags = 0;

    Status = FltSetTransactionContext(FltObjects->Instance, FltObjects->Transaction, FLT_SET_CONTEXT_KEEP_IF_EXISTS, TransactionContext, (PFLT_CONTEXT*)&OldTransactionContext);

    if (!NT_SUCCESS(Status))
    {
        FltReleaseContext(TransactionContext);

        if (Status != STATUS_FLT_CONTEXT_ALREADY_DEFINED)
        {
            return Status;
        }

        if (FlagOn(OldTransactionContext->Flags, ENLISTED_IN_TRANSACTION))
        {

            FltReleaseContext(OldTransactionContext);
            return STATUS_SUCCESS;
        }

        TransactionContext = OldTransactionContext;
    }

    ENLIST_IN_TRANSACTION: 
        
        Status = FltEnlistInTransaction(FltObjects->Instance, FltObjects->Transaction, TransactionContext, FLT_MAX_TRANSACTION_NOTIFICATIONS);

        if (!NT_SUCCESS(Status))
        {

            if (Status == STATUS_FLT_ALREADY_ENLISTED)
            {
                Status = STATUS_SUCCESS;
            }
            else
            {
                FltDeleteContext(TransactionContext);
            }

            FltReleaseContext(TransactionContext);
            return Status;
        }

        InterlockedOr((volatile LONG*)&TransactionContext->Flags, ENLISTED_IN_TRANSACTION);

        FltReleaseContext(TransactionContext);

        TransactionCallback(FltObjects, 0, 0);
        return STATUS_SUCCESS;
}

NTSTATUS
TransactionCallback(
    _In_     PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PFLT_CONTEXT TransactionContext,
    _In_opt_ ULONG NotificationMask
) {
    UNREFERENCED_PARAMETER(TransactionContext);

    PFS_TELEMETRY Log = CreateLog();

    if (Log != 0)
    {
        KeQuerySystemTime(&Log->OriginatingTime);

        PDEVICE_OBJECT DeviceObject;
        NTSTATUS       Status = FltGetDeviceObject(FltObjects->Volume, &DeviceObject);

        if (NT_SUCCESS(Status))
        {
            ObDereferenceObject(DeviceObject);
        }
        else
        {
            DeviceObject = 0;
        }

        Log->MajorFunction = TRANSACTION_NOTIFY;

        Log->MinorFunction = NotificationMask;

        Log->DeviceObject = (SIZE_T)DeviceObject;
        Log->FileObject = (SIZE_T)FltObjects->FileObject;
        Log->Transaction = (SIZE_T)FltObjects->Transaction;
        Log->ProcessId = PsGetCurrentProcessId();
        Log->ThreadId = PsGetCurrentThreadId();

        InsertLog(Log);
    }

    return STATUS_SUCCESS;
}

FLT_POSTOP_CALLBACK_STATUS
PostOperationCallback(
    _Inout_ PFLT_CALLBACK_DATA        Data,
    _In_    PCFLT_RELATED_OBJECTS     FltObjects,
    _In_    PVOID                     CompletionContext,
    _In_    FLT_POST_OPERATION_FLAGS  Flags
) {

    PFS_TELEMETRY Log = (PFS_TELEMETRY)CompletionContext; 

    if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING))
    {
        FreeLog(Log);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    KeQuerySystemTime(&Log->CompletionTime);

    Log->Status = Data->IoStatus.Status;
    Log->Information = Data->IoStatus.Information;

    InsertLog(Log);

    if ((FltObjects->Transaction != 0)
        &&
        (Data->Iopb->MajorFunction == IRP_MJ_CREATE)
        &&
        (Data->IoStatus.Status == STATUS_SUCCESS))
    {
        EnlistInTransaction(FltObjects);
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}