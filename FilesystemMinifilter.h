#pragma once
#include <ntifs.h>
#include <fltKernel.h>

typedef struct _TRANSACTION_CONTEXT
{
	ULONG Flags;
}TRANSACTION_CONTEXT, * PTRANSACTION_CONTEXT;

extern PFLT_FILTER Filter;
extern PFLT_PORT FilterPort;
extern UNICODE_STRING FilterName;
extern PFLT_PORT ClientPort;

NTSTATUS FilterUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);
NTSTATUS CreateFilterPort();
VOID PortClientDisconnect(_In_opt_ PVOID ConnectionCookie);

NTSTATUS PortClientMessage(
    _In_ PVOID ConnectionCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
);

NTSTATUS PortClientConnect(
    _In_ PFLT_PORT _ClientPort,
    _In_ PVOID ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
);