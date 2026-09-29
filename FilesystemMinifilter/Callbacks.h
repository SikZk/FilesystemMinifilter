#pragma once
#include <ntifs.h>
#include <fltKernel.h>

#define FILE_DISPOSITION_FLAG_DELETE 0x00000001

#define SAFE_ACCESS_MASK (        \
    FILE_READ_DATA             |  \
    FILE_READ_ATTRIBUTES       |  \
    FILE_READ_EA               |  \
    FILE_LIST_DIRECTORY        |  \
    FILE_TRAVERSE              |  \
    FILE_EXECUTE               |  \
    READ_CONTROL               |  \
    SYNCHRONIZE                |  \
    ACCESS_SYSTEM_SECURITY     |  \
    GENERIC_READ               |  \
    GENERIC_EXECUTE            )

extern CONST UNICODE_STRING ProtectedDir;

typedef struct _TRANSACTION_CONTEXT {
    ULONG Flags;
} TRANSACTION_CONTEXT, * PTRANSACTION_CONTEXT;

EXTERN_C NTKERNELAPI BOOLEAN NTAPI PsIsProtectedProcess(
	_In_ PEPROCESS Process
);

FLT_PREOP_CALLBACK_STATUS
PreOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_    PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS
PostOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

NTSTATUS
TransactionCallback(
	_In_     PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PFLT_CONTEXT TransactionContext,
	_In_opt_ ULONG NotificationMask
);