import ctypes
from ctypes import wintypes
import uuid

import globais
from lang_utils import text_interface_dict
text_interface = text_interface_dict[globais.configuracao["default_lang"]]

# inicio codigo para usar wintrust.dll + kernel32.dll
debug = True

wt = ctypes.windll.wintrust
k32 = ctypes.windll.kernel32

CreateFileW = getattr(k32, "CreateFileW")
CloseHandle = getattr(k32, "CloseHandle")

CryptCATAdminAcquireContext = getattr(wt, "CryptCATAdminAcquireContext")
CryptCATAdminCalcHashFromFileHandle = getattr(wt, "CryptCATAdminCalcHashFromFileHandle")
CryptCATAdminEnumCatalogFromHash = getattr(wt, "CryptCATAdminEnumCatalogFromHash")
CryptCATCatalogInfoFromContext = getattr(wt, "CryptCATCatalogInfoFromContext")
CryptCATAdminReleaseCatalogContext = getattr(wt, "CryptCATAdminReleaseCatalogContext")
CryptCATAdminReleaseContext = getattr(wt, "CryptCATAdminReleaseContext")
WinVerifyTrust = getattr(wt, "WinVerifyTrust")

# --- Protótipos Estritos (Usando c_void_p para evitar Overflow e POINTER) ---
CryptCATAdminAcquireContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
CryptCATAdminCalcHashFromFileHandle.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
CryptCATAdminEnumCatalogFromHash.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p]
CryptCATCatalogInfoFromContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD]
CryptCATAdminReleaseCatalogContext.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]


class GUID(ctypes.Structure):
    _fields_ = [("D1", wintypes.DWORD), ("D2", wintypes.WORD), ("D3", wintypes.WORD), ("D4", wintypes.BYTE * 8)]

    @classmethod
    def from_str(cls, s):
        u = uuid.UUID(s)
        return cls(u.time_low, u.time_mid, u.time_hi_version, (ctypes.c_ubyte * 8)(*u.bytes[8:]))


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("path", wintypes.LPCWSTR), ("h", wintypes.HANDLE), ("pg", ctypes.c_void_p)]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("ver", wintypes.DWORD), ("cat_path", wintypes.LPCWSTR),
                ("tag", wintypes.LPCWSTR), ("file_path", wintypes.LPCWSTR), ("h_member", wintypes.HANDLE),
                ("p_hash", ctypes.c_void_p), ("cb_hash", wintypes.DWORD), ("p_ctx", ctypes.c_void_p)]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("p_policy", ctypes.c_void_p), ("p_sip", ctypes.c_void_p),
                ("ui", wintypes.DWORD), ("revoke", wintypes.DWORD), ("choice", wintypes.DWORD),
                ("union_ptr", ctypes.c_void_p), ("action", wintypes.DWORD), ("h_state", wintypes.HANDLE),
                ("url", wintypes.LPCWSTR), ("prov", wintypes.DWORD), ("ctx_ui", wintypes.DWORD)]

class CI(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("path", wintypes.WCHAR * 260)]

def is_microsoft_signed(caminho):
    v2_guid = GUID.from_str("{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}")

    # 1. TESTE DIRETO
    fi = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), caminho, None, None)
    wd = WINTRUST_DATA(cb=ctypes.sizeof(WINTRUST_DATA), ui=2, revoke=0, choice=1,
                       union_ptr=ctypes.addressof(fi), action=1)

    res = WinVerifyTrust(None, ctypes.byref(v2_guid), ctypes.byref(wd))
    wd.action = 2
    WinVerifyTrust(None, ctypes.byref(v2_guid), ctypes.byref(wd))
    if res == 0:
        return True, f"{text_interface["oficial_embedded_cert"]}: {caminho}"

    # 2. TESTE CATÁLOGO (Fallback)
    if res == -2146762496:
        h_cat_admin = wintypes.HANDLE()
        if not CryptCATAdminAcquireContext(ctypes.byref(h_cat_admin), None, 0):
            return False, text_interface["error_admin"]

        h_file = CreateFileW(caminho, 0x80000000, 7, None, 3, 0, None)
        if h_file == -1:
            return False, text_interface["error_file"]

        h_buf = (ctypes.c_byte * 64)()
        h_sz = wintypes.DWORD(ctypes.sizeof(h_buf))
        CryptCATAdminCalcHashFromFileHandle(h_file, ctypes.byref(h_sz), ctypes.byref(h_buf), 0)
        CloseHandle(h_file)

        cat_ctx = CryptCATAdminEnumCatalogFromHash(h_cat_admin, ctypes.byref(h_buf), h_sz, 0, None)
        if not cat_ctx:
            CryptCATAdminReleaseContext(h_cat_admin, 0)
            return False, f"{text_interface["not_signed"]}: {caminho}"

        struct_ci = CI(ctypes.sizeof(CI))
        CryptCATCatalogInfoFromContext(cat_ctx, ctypes.byref(struct_ci), 0)

        tag = "".join(f"{b & 0xff:02X}" for b in h_buf[:h_sz.value])

        # Correção aqui: usando cast() para evitar erro de conversão de ponteiro
        c_info = WINTRUST_CATALOG_INFO(
            cb=ctypes.sizeof(WINTRUST_CATALOG_INFO),
            ver=0,
            cat_path=struct_ci.path,
            tag=tag,
            file_path=caminho,
            h_member=None,
            p_hash=ctypes.cast(h_buf, ctypes.c_void_p),  # Converte buffer para ponteiro genérico
            cb_hash=h_sz,
            p_ctx=cat_ctx
        )

        wd_cat = WINTRUST_DATA(cb=ctypes.sizeof(WINTRUST_DATA), ui=2, revoke=0, choice=2,
                               union_ptr=ctypes.addressof(c_info), action=1)

        res_cat = WinVerifyTrust(None, ctypes.byref(v2_guid), ctypes.byref(wd_cat))

        # Cleanup
        wd_cat.action = 2
        WinVerifyTrust(None, ctypes.byref(v2_guid), ctypes.byref(wd_cat))
        CryptCATAdminReleaseCatalogContext(h_cat_admin, cat_ctx, 0)
        CryptCATAdminReleaseContext(h_cat_admin, 0)

        if res_cat == 0:
            return True, f"{text_interface["oficial_cat_cert"]}: {caminho}"
        else:
            return False, f"{text_interface["not_trusted"]} ({hex(res_cat & 0xFFFFFFFF)}): {caminho}"
    return False, f"{text_interface["not_trusted"]} ({hex(res & 0xFFFFFFFF)}): {caminho}"
