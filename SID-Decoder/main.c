// Created by: EvilIncC0RP

#include <stdio.h>
#include <Windows.h>

#include "sid_decoder.h"


// Generated SID payload
static const SIZE_T g_OriginalSize = 70;
static const WCHAR* const g_SidPayload[] = {
    L"S-1-5-17040130-100993031-185207052-219156238-303109139-387323160-421272346-505225247-589439268-623388454-707341355-791555376-825504562-909457463-993671484",
    L"S-1-5-1027620670-1111573571-4605184"
};
static const SIZE_T g_SidCount = _countof(g_SidPayload);


static VOID PrintBuffer(
    const BYTE* buffer,
    SIZE_T bufferSize
)
{
    if (buffer == NULL ||
        bufferSize == 0)
    {
        return;
    }

    for (SIZE_T i = 0;
        i < bufferSize;
        i++)
    {
        printf(
            "%02X ",
            buffer[i]
        );
    }

    printf("\n");
}


int main(void)
{
    PBYTE decodedPayload = NULL;
    SIZE_T decodedPayloadSize = 0;

    if (!DecodeSidPayload(
        g_SidPayload,
        g_SidCount,
        g_OriginalSize,
        &decodedPayload,
        &decodedPayloadSize
    ))
    {
        printf(
            "[-] DecodeSidPayload failed.\n"
        );

        return 1;
    }

    printf(
        "[+] Decoded payload size: "
        "%zu bytes\n",
        decodedPayloadSize
    );

    printf(
        "[+] Decoded payload:\n"
    );

    PrintBuffer(
        decodedPayload,
        decodedPayloadSize
    );

    FreeDecodedPayload(
        decodedPayload
    );

    decodedPayload = NULL;

    return 0;
}
