#pragma once
#include <Windows.h>
#include <string>
#include <format>

#include "../FilesystemMinifilter/FsTelemetry.h"

BOOLEAN InitializeEventLog();
void DestroyEventLog();
VOID LogFsTelemetry(_In_ PFS_TELEMETRY Log);
