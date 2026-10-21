#pragma once

#include <Windows.h>

BOOL DecodeSidPayload(
    PCWSTR const* sidPayload,
    SIZE_T sidCount,
    SIZE_T originalSize,
    PBYTE* outputBuffer,
    SIZE_T* outputSize
);

VOID FreeDecodedPayload(
    PBYTE decodedPayload
);
