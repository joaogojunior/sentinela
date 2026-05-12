import ctypes
from ctypes import wintypes

# Funcao de baixo nivel que obtem o "last modified time" e o tamanho de um determinado arquivo.
# Foi necessario recorrer a chamadas do kernel32 para garantir que os dados sao identicos aos
# que seriam obtido pelo driver do kernel.
def get_nt_metadata(file_path):
    # Definições de constantes do Windows
    # 1. Configuração do Kernel32 com tipos explícitos para o PyCharm
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

    # Declaramos as assinaturas para a IDE parar de reclamar
    kernel32.CreateFileW.argtypes = [
        ctypes.wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
    ]

    kernel32.CreateFileW.restype = wintypes.HANDLE

    kernel32.GetFileTime.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p
    ]

    kernel32.GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    handle = kernel32.CreateFileW(
        file_path,
        win32file.FILE_ATTRIBUTE_NORMAL,
        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
        None,
        win32file.OPEN_EXISTING,
        0,
        None
    )

    if handle == win32file.INVALID_HANDLE_VALUE:
        return 0, 0

    try:
        # 1. Obtém o FILETIME (64-bit int que o Kernel usa)
        # O kernel preenche essas estruturas por referência
        creation_time = wintypes.FILETIME()
        access_time = wintypes.FILETIME()
        write_time = wintypes.FILETIME()

        if not kernel32.GetFileTime(handle, ctypes.byref(creation_time),
                                    ctypes.byref(access_time),
                                    ctypes.byref(write_time)):
            return 0, 0

        # Combina os dois DWORDs de 32 bits em um único inteiro de 64 bits
        mtime = (write_time.dwHighDateTime << 32) + write_time.dwLowDateTime

        # 2. Obtém o Tamanho do Arquivo de 64 bits (LARGE_INTEGER)
        file_size = ctypes.c_int64()
        if not kernel32.GetFileSizeEx(handle, ctypes.byref(file_size)):
            return 0, 0
        kernel32.CloseHandle(handle)
        return mtime, file_size.value
    except:
        kernel32.CloseHandle(handle)
        return 0, 0