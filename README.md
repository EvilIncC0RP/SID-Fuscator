# SID-Fuscator

SID-Fuscator is a Windows C project that converts a byte array into one or more valid SID strings. A separate decoder restores the original bytes.

The project demonstrates binary-data processing, pointer arithmetic, four-byte block transformations, DWORD packing, Windows SID APIs, and manual memory management in C.

> This is reversible obfuscation, not encryption.

## How it works

The fuscator performs the following operations:

```text
Input bytes
    -> zero padding to a multiple of 4
    -> permutation of each 4-byte block
    -> packing blocks into DWORD values
    -> storing DWORD values as SID subauthorities
```

The decoder reverses the process:

```text
SID strings
    -> extraction of DWORD values
    -> unpacking DWORD values into bytes
    -> restoration of each 4-byte block
    -> removal of padding using the original size
```

The rotation used for each block is calculated with:

```c
rotation = (blockIndex % 3) + 1;
```

This creates a repeating rotation sequence of `1, 2, 3`.

One SID can store up to 15 DWORD values, equivalent to 60 transformed bytes. Larger inputs are automatically divided between multiple SID strings.

## Project structure

```text
SID-Fuscator/
├── SID-Fuscation/
│   ├── input_payload.h
│   ├── main.c
│   └── SID-Fuscation.vcxproj
├── SID-Decoder/
│   ├── main.c
│   ├── sid_decoder.c
│   ├── sid_decoder.h
│   └── SID-Decoder.vcxproj
├── SID-Fuscation.sln
├── LICENSE
└── README.md
```

## Requirements

- Windows 10 or Windows 11
- Visual Studio 2022
- Desktop development with C++ workload
- Windows SDK
- MSVC v143 toolset

## Build

1. Open `SID-Fuscation.sln` in Visual Studio 2022.
2. Select `Release` and `x64`.
3. Select **Build -> Build Solution**.

The executables will be created in:

```text
x64\Release\SID-Fuscation.exe
x64\Release\SID-Decoder.exe
```

## Input

Place the input bytes in `SID-Fuscation/input_payload.h`:

```c
static const BYTE g_InputPayload[] = {
    0x10, 0x20, 0x30, 0x40,
    0x50, 0x60, 0x70, 0x80,
    0x90, 0xA0
};

static const SIZE_T g_InputPayloadSize =
    sizeof(g_InputPayload);
```

The size is stored explicitly because binary data may contain `0x00` bytes.

## Usage

Run the fuscator:

```powershell
.\x64\Release\SID-Fuscation.exe
```

Available output modes:

```text
[1] Print SID payload to console
[2] Write generated_payload.h
[3] Print and write file
```

Optional debug output displays the original, padded, permuted, and packed data together with the generated SID strings.

Example generated output:

```c
static const SIZE_T g_OriginalSize = 10;

static const WCHAR* const g_SidPayload[] = {
    L"S-1-5-272642080-1615888496-10522624"
};

static const SIZE_T g_SidCount =
    sizeof(g_SidPayload) /
    sizeof(g_SidPayload[0]);
```

## Decoder

The decoder exposes two public functions:

```c
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
```

`DecodeSidPayload` allocates the restored buffer and returns it through `outputBuffer`. The caller must release it with `FreeDecodedPayload`.

## Notes

- The project is Windows-specific.
- DWORD packing uses `memcpy` instead of pointer casting.
- `HeapAlloc` memory is released with `HeapFree`.
- Memory returned by `ConvertStringSidToSidW` is released with `LocalFree`.
- The transformation is deterministic and reversible.

## Author

Created by **EvilIncC0RP**.

## License

Released under the [MIT License](LICENSE).
