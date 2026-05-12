import queue
import pywintypes
import threading
from criador_json import criador_json
# from sys import argv as sys_argv
from os import path

arquivo_configuracao = "sentinela.json"

versao_atual = "v0.2"

# configuracao padrão inicial
configuracao_padrao = {
    "scan_all": False,
    "logging": False,
    "debug": True,
    "clamav_path": "C:\\Sentinela\\clamav",
    "num_workers": 4,
    "update_interval": 6,
    "default_codepage": "cp850",
    "default_lang": "pt-BR",
    "worker_names": [
        "Tron",
        "CLU",
        "Data",
        "TARS",
        "HAL",
        "KITT",
        "C3PO",
        "R2D2",
        "K2SO",
        "BB-8",
        "T808",
        "T1000",
        "Jarvis",
        "Ultron",
        "GlaDOS",
        "Johnny5",
        "I-Zack"
    ]}

configuracao_alterada = False

# se nao houver arquivo de configuracao inicializa com valores padroes, se houver carrega
# os valores do arquivo
# caminho_home = path.dirname(sys_argv[0])

configuracao = criador_json.carrega_ou_cria_config(arquivo_configuracao, configuracao_padrao)

verdict_queue = queue.Queue()
clamd_pid = 0
# h_driver: Optional[pywintypes.HANDLE] = None
# Use aspas para que o Python não tente avaliar pywintypes.HANDLE como um tipo real no carregamento
h_driver: "pywintypes.HANDLE" = None

startup_scan_list = [
    "ntdll.dll", "kernelbase.dll", "msvcp_win.dll",
    "gdi32full.dll", "comctl32.dll", "crypt32.dll",
    "bcrypt.dll", "cfgmgr32.dll", "ucrtbase.dll",
    "wintrust.dll", "version.dll", "vcruntime140.dll",
    "vcruntime140_1.dll", "userenv.dll", "profapi.dll",
    "powrprof.dll", "hal.dll", "ci.dll", "PSAPI.DLL",
    "ws2_32.dll", "WLDAP32.dll", "advapi32.dll", "dpapi.dll",
    "user32.dll", "shlwapi.dll", "shell32.dll", "shcore.dll",
    "Setupapi.dll", "sechost.dll", "rpcrt4.dll",
    "oleaut32.dll", "ole32.dll", "NORMALIZ.dll",
    "msvcrt.dll", "MSCTF.dll", "kernel32.dll", "imm32.dll",
    "IMAGEHLP.dll", "gdiplus.dll", "gdi32.dll", "difxapi.dll",
    "coml2.dll", "comdlg32.dll", "combase.dll", "clbcatq.dll",
    "appinfo.dll", "uxtheme.dll", "dwmapi.dll", "rsaenh.dll",
    "authz.dll", "dxgi.dll", "d2d1.dll", "NetSetupEngine.dll",
    "nsi.dll", "winnsi.dll", "ImplatSetup.dll", "kernel.appcore.dll",
    "bcryptprimitives.dll", "umpdc.dll", "win32u.dll", "cryptsp.dll",
    "Windows.StateRepositoryCore.dll", "sspicli.dll", "msasn1.dll",
    "winhttp.dll", "cryptbase.dll", "WinTypes.dll", "CoreMessaging.dll",
    "winmm.dll", "secur32.dll", "smss.exe", "csrss.exe",
    "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe",
    "svchost.exe", "SecurityHealthService.exe", "Wininit.exe",
    "consent.exe", "securekernel.exe", "lsaiso.exe"
]

buffer_size = 1024  # Tamanho inicial padrão

workers = []

driver_lock = threading.Lock()

maior_tempo = 0

media_tempo = 0

# cria .conf
if not path.isfile("fangfrisch.conf"):
    with open("fangfrisch.conf", "w") as novo_conf:
        novo_conf.write("[DEFAULT]\ndb_url = sqlite:///C:\\Sentinela\\fangfrisch.db\\\nlocal_directory = "
                        "C:\\Sentinela\\clamav\\database\\\n\n[sanesecurity]\nenabled = yes\n\n[urlhaus]\n"
                        "enabled = yes\n\n[malwarepatrol]\nenabled = no\n"
                        "# Requer cadastro gratuito em malwarepatrol.net\nreceipt = preencha_com_o_receipt_recebido\n"
                        "product = 8 (para ClamAV)\n\n[securiteinfo]\nenabled = no\n"
                        "# Requer cadastro em securiteinfo.com\ncustomer_id = preencha_com_o_customer_id_recebido\n\n"
                        "[linuxmalwaredetect]\nenabled = yes")
        novo_conf.close()