#pragma once
#include <ntifs.h>
#include <fltKernel.h>

#define MAX_LOG_COUNT 512
#define TRANSACTION_NOTIFY      (ULONG)(-40)
#define ENLISTED_IN_TRANSACTION 0x1

extern LIST_ENTRY LogList;
extern KSPIN_LOCK LogLock;
extern volatile LONG LogCount;

typedef struct _FS_OPERATION_DATA
{
    //
    // Populated based on MajorFunction. Only one member is valid at a time.
    //
    union
    {
        //
        // IRP_MJ_CREATE
        //
        struct
        {
            ULONG   EcpCount;
            BOOLEAN IsRemoteOpen;
            NETWORK_OPEN_LOCATION_QUALIFIER NetworkLocation;
            WCHAR   ShareName[128];
            WCHAR   RemoteAddress[46];
            USHORT  RemotePort;
        } Create;

        //
        // IRP_MJ_SET_INFORMATION
        //
        struct
        {
            FILE_INFORMATION_CLASS InfoClass;

            union
            {
                //
                // FileRenameInformation / FileRenameInformationEx
                //
                struct
                {
                    BOOLEAN ReplaceIfExists;
                    WCHAR   TargetFileName[520];
                } Rename;

                //
                // FileDispositionInformation / FileDispositionInformationEx
                //
                struct
                {
                    BOOLEAN DeleteFile;
                } Disposition;

                //
                // FileBasicInformation (can detect timestamp stomping)
                //
                struct
                {
                    LARGE_INTEGER CreationTime;
                    LARGE_INTEGER LastWriteTime;
                    ULONG         FileAttributes;
                } Basic;
            };
        } SetInformation;
    } Enrichment;

} FS_OPERATION_DATA, * PFS_OPERATION_DATA;

typedef struct _FS_TELEMETRY
{
    LIST_ENTRY              List;

    //
    // When we received the request (pre-op)
    //

    LARGE_INTEGER OriginatingTime;

    //
    // When the request was completed (post-op)
    //

    LARGE_INTEGER CompletionTime;

    //
    // Identifies which volume the operation occurred on
    //

    SIZE_T         DeviceObject;

    //
    // Identifies the handle used in the operation
    //

    SIZE_T         FileObject;

    //
    // Identifier of the transaction associated with this operation. 0 if not part of a transaction
    //

    SIZE_T         Transaction;

    //
    // Calling process and thread
    //

    HANDLE         ProcessId;
    HANDLE         ThreadId;

    //
    // Flags from the original IRP
    //

    ULONG          IrpFlags;

    //
    //
    //

    ULONG          Flags;

    //
    // Major and minor function code
    //

    ULONG          MajorFunction;
    ULONG          MinorFunction;

    //
    // Parameters to the function
    //

    FLT_PARAMETERS Parameters;

    //
    // Status of the operation
    //

    NTSTATUS       Status;

    //
    // Request-dependant value related to the result of the I/O operation
    //

    ULONG_PTR      Information;

    //
    // File attributes populated if the operation is done on a file
    //

    WCHAR          FileName[520];    // Name of the file
    LARGE_INTEGER  FileSize;         // Its size
    ULONG          FileAttributes;   // FILE_ATTRIBUTE_*

    //
    // Additional information obtained from the parameters
    //

    FS_OPERATION_DATA OpData;
} FS_TELEMETRY, * PFS_TELEMETRY;

NTSTATUS
SendLogs(
    _In_  PVOID  OutputBuffer,
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