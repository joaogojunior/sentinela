#ifndef _SHARED_LOGIC_H_
#define _SHARED_LOGIC_H_

#ifdef _KERNEL_MODE
// Se estiver no Driver, usa as definições reais do Windows
#include <ntddk.h>
// #include <ntstrsafe.h>

#else
// --- PONTE DE COMPATIBILIDADE ---

// 1. Inclusões básicas de sistema
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string.h>
#include <wchar.h>


// 2. Tipos Primitivos (Sem eles, nada abaixo funciona)
// typedef unsigned short USHORT;
// typedef wchar_t WCHAR, * PWSTR, * PWCH, * PCWSTR;
// typedef unsigned char BYTE, * PCHAR;
// typedef int BOOLEAN;
// typedef void VOID, * PVOID;
// typedef long NTSTATUS;
// typedef size_t SIZE_T;
// typedef unsigned long ULONG;

#define TRUE 1
#define FALSE 0
#define FILE_READ_ATTRIBUTES 0x0080
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64

// 3. A STRUCT (Precisa vir antes das funções que usam PUNICODE_STRING)
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef const UNICODE_STRING* PCUNICODE_STRING;

// 4. Mocks de Tipos de Objeto
typedef unsigned long ACCESS_MASK;

// Estruturas simplificadas para o Mock
typedef struct _DEVICE_OBJECT {
    PVOID DeviceExtension;
    // No seu caso, podemos guardar o nome do volume aqui para o próximo mock ler
    WCHAR VolumeName[64];
} DEVICE_OBJECT, * PDEVICE_OBJECT;

typedef struct _FILE_OBJECT {
    PDEVICE_OBJECT DeviceObject;
} FILE_OBJECT, * PFILE_OBJECT;


// 5. Protótipos e Inline Functions (Mocks)
#define RtlCopyMemory memcpy
#define RtlZeroMemory(D, L) memset(D, 0, L)
#define DbgPrint printf
#define RTL_CONSTANT_STRING(s) { sizeof(s) - sizeof(WCHAR), sizeof(s), (PWSTR)s }
#define ExFreePool(P) free(P)
#define ExFreePoolWithTag(P, T) free(P)
#define ObDereferenceObject(P)
#define ExAllocatePool2(S, T) malloc(S)

inline HRESULT RtlUnicodeStringCopy(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString) {
    if (!DestinationString || !SourceString || !DestinationString->Buffer || !SourceString->Buffer)
        return E_INVALIDARG;

    // Calcula quantos caracteres cabem no destino (incluindo espaço para o \0)
    size_t destCapacityInChars = DestinationString->MaximumLength / sizeof(WCHAR);
    // Quantos caracteres copiar da origem
    size_t charsToCopy = SourceString->Length / sizeof(WCHAR);

    // wcsncpy_s copia os caracteres e garante o terminador nulo \0
    errno_t err = wcsncpy_s(DestinationString->Buffer, destCapacityInChars, SourceString->Buffer, charsToCopy);

    if (err == 0) {
        // Atualiza o Length (tamanho em bytes sem o \0)
        DestinationString->Length = (USHORT)(wcsnlen_s(DestinationString->Buffer, destCapacityInChars) * sizeof(WCHAR));
        return S_OK;
    }

    return E_FAIL;
}

// Simulação de RtlUnicodeStringCat usando wcscat_s
inline HRESULT RtlUnicodeStringCat(PUNICODE_STRING DestinationString, PCUNICODE_STRING SourceString) {

    if (!DestinationString || !SourceString || !DestinationString->Buffer || !SourceString->Buffer) {
        return E_INVALIDARG;
    }

    // Calcula a capacidade total do buffer de destino em caracteres (WCHARs)
    size_t destCapacityInChars = DestinationString->MaximumLength / sizeof(WCHAR);

    // wcscat_s anexa SourceString->Buffer ao final de DestinationString->Buffer
    // Ela verifica automaticamente se há espaço suficiente e garante o \0 final.
    errno_t err = wcscat_s(DestinationString->Buffer, destCapacityInChars, SourceString->Buffer);

    if (err == 0) {
        // Atualiza o novo comprimento da string (em bytes, sem o \0)
        DestinationString->Length = (USHORT)(wcslen(DestinationString->Buffer) * sizeof(WCHAR));
        return S_OK;
    }

    // Retorna erro caso o buffer seja insuficiente (STRSAFE_E_INSUFFICIENT_BUFFER ou similar)
    return E_FAIL;
}

inline VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString) {
    if (SourceString) {
        USHORT len = (USHORT)(wcslen(SourceString) * sizeof(WCHAR));
        DestinationString->Length = len;
        DestinationString->MaximumLength = len + sizeof(WCHAR);
        DestinationString->Buffer = (PWSTR)SourceString;
    }
}

inline BOOLEAN RtlPrefixUnicodeString(PUNICODE_STRING Prefix, PUNICODE_STRING String, BOOLEAN Case) {
    if (!Prefix || !String || String->Length < Prefix->Length) return FALSE;
    return _wcsnicmp(String->Buffer, Prefix->Buffer, Prefix->Length / 2) == 0;
}

inline VOID RtlCopyUnicodeString(PUNICODE_STRING Dest, PUNICODE_STRING Src) {
    USHORT len = (Src->Length < Dest->MaximumLength) ? Src->Length : Dest->MaximumLength;
    memcpy(Dest->Buffer, Src->Buffer, len);
    Dest->Length = len;
}

// Mock da Função
NTSTATUS IoGetDeviceObjectPointer(
    PUNICODE_STRING ObjectName,
    ACCESS_MASK DesiredAccess,
    PFILE_OBJECT* FileObject,
    PDEVICE_OBJECT* DeviceObject
) {
    if (!ObjectName || !FileObject || !DeviceObject)
        return (NTSTATUS)0xC000000DL; // STATUS_INVALID_PARAMETER

    //printf("[MOCK] Buscando objeto para: %wZ\n", ObjectName);

    // 2. Aloca o DeviceObject
    PDEVICE_OBJECT pDev = (PDEVICE_OBJECT)malloc(sizeof(DEVICE_OBJECT));

    if (!pDev) {
        if (pDev) free(pDev);
        return (NTSTATUS)0xC000009A; // STATUS_INSUFFICIENT_RESOURCES
    }

    // 3. Simula a associação
    // Copiamos o nome para o DeviceObject para que o mock da IoQuery possa usar depois
    wcsncpy_s(pDev->VolumeName, ObjectName->Buffer, ObjectName->Length / sizeof(WCHAR));
    pDev->VolumeName[ObjectName->Length / sizeof(WCHAR)] = L'\0';

    // 4. Retorna os ponteiros (o "pulo do gato" de novo)
    *FileObject = NULL;
    *DeviceObject = pDev;

    //printf("[MOCK] Objeto criado em: Dev=%p\n", pDev);
    return 0; // STATUS_SUCCESS
}

inline NTSTATUS IoVolumeDeviceToDosName(PDEVICE_OBJECT DeviceObj, PUNICODE_STRING DosPath) {
    if (!DeviceObj || !DosPath) return (NTSTATUS)0xC000000DL;
    
    UNICODE_STRING DeviceName;
    DeviceName.Buffer = (PWCH)DeviceObj->VolumeName;
    DeviceName.Length = (USHORT)wcslen(DeviceObj->VolumeName) * sizeof(WCHAR);
    DeviceName.MaximumLength = DeviceName.Length;

    int pathLen = DeviceName.Length / sizeof(WCHAR);
    WCHAR driveLetter = L'Z';
    WCHAR lastChar;

    // ... (sua lógica de descoberta da driveLetter continua igual) ...
    if (pathLen > 0) {
        // Pega o caractere na última posição válida
        lastChar = DeviceName.Buffer[pathLen - 1];
        //printf("lastChar: %lc\n", lastChar);
        // Print de debug no Console (Ring 3)
        // %lc é para caractere largo (wchar_t)

        // A lógica de conversão que você pediu:
        driveLetter = (WCHAR)(L'A' + (lastChar - L'1'));
        //printf("driveLetter: %lc\n", driveLetter);
    }
    // O Kernel NÃO aloca a estrutura UNICODE_STRING, ele preenche a que você passou.
    // Ele aloca apenas o BUFFER. No Kernel seria PagedPool, no Mock usamos malloc.

    DosPath->MaximumLength = 14;
    DosPath->Buffer = (PWCH)malloc(14);

    if (!DosPath->Buffer) {
        return (NTSTATUS)0xC000009A;
    }

    // Preenche o buffer da estrutura que o chamador forneceu
    swprintf_s(DosPath->Buffer, 7, L"%lc:", driveLetter);
    DosPath->Length = 2 * sizeof(WCHAR); // 4 bytes

    // NÃO faça "DosPath = dosName", pois DosPath já é o endereço correto 
    // da variável 'dosName' que você criou no código que chama.

    //printf("[MOCK] Retornando para o chamador: %wZ\n", DosPath);
    return 0;
}

// Mock do SharedUserData para o Caso 3
struct MOCK_USER_DATA { WCHAR NtSystemRoot[260]; };
static MOCK_USER_DATA MockData = { L"C:\\Windows" };
#define SharedUserData (&MockData)

#endif

#endif