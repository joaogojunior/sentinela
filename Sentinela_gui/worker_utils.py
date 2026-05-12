import struct
import random
import time

import pywintypes
import os
import threading
from time import sleep
from io import BytesIO

try:
    import win32file
    import win32event
except ImportError:
    from win32 import win32file, win32event

import clamd_utils
import drive_utils
import globais

from lang_utils import text_interface_dict
text_interface = text_interface_dict[globais.configuracao["default_lang"]]

logfile = "workers_log.txt"
global_lock = threading.Lock()
tempo_lock = threading.Lock()

ERROR_NOT_FOUND = 1168        # Corresponde ao STATUS_NOT_FOUND do Driver
ERROR_INVALID_HANDLE = 6      # Corresponde ao STATUS_INVALID_HANDLE
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NO_MORE_FILES = 259


class MeuWorker(threading.Thread):
    def __init__(self, monitor_event, nome):
        super().__init__(name=nome)
        self.monitor_event = monitor_event
        # Cria o evento de saída dentro da própria classe
        self.exit_handle = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def run(self):
        print_log(f"[+] Worker {self.name} {text_interface["started"]}.")
        globais.verdict_queue.put(("WORKER", "-", f"[+] Worker {self.name} {text_interface["started"]}.", text_interface["tag_ok"]))
        # resultado é o indice dessa lista
        handles = [self.monitor_event, self.exit_handle]

        while self.running:
            # Espera por qualquer um dos dois eventos
            result = win32event.WaitForMultipleObjects(handles, False, win32event.INFINITE)

            # result é o indice do objeto retornado, Se for o 1 eh o exit_handle
            if result == 1:
                print_log(f"[-] Worker {self.name} {text_interface["received_exit"]}")
                break

            # se chegou aqui, trabalha...
            cd: clamd_utils.clamd.ClamdNetworkSocket | None = clamd_utils.conecta_clamd(self.name)

            self.fazer_trabalho(cd)

        print_log(f"[!] Worker {self.name} {text_interface["ended"]}")

    def stop(self):
        win32event.SetEvent(self.exit_handle)

    def fazer_trabalho(self, cd):
        workload(self.name, cd)

def print_log(texto):
    if globais.configuracao["debug"]:
        print(texto)
    if globais.configuracao["logging"]:
        with open(logfile, "a") as log:
            log.write(texto + "\n")

def encerrar_comunicacao():
    try:
        if globais.h_driver:
            win32file.DeviceIoControl(globais.h_driver, 0x22200C, None, 0)
            print_log(text_interface["driver_restarted"])
            # Fecha o handle do driver e do evento
            globais.h_driver.close()
    except Exception as e:
        print_log(f"{text_interface["error_unreg"]}: {e}")
    print_log(text_interface["driver_unloaded"])

def registra_monitor(h_driver, my_pid, clamd_pid):
    h_driver_ptr = h_driver.handle
    h_event = win32event.CreateEvent(None, 0, 0, None)
    # Monta o pacote: MonitorPid (Q) + EventHandle (Q)
    # Em sistemas 64-bit, o handle e o pid são 8 bytes cada.
    packet = struct.pack("QQQ", int(my_pid), int(clamd_pid), int(h_event))
    win32file.DeviceIoControl(h_driver_ptr, 0x222000, packet, None)
    return h_driver_ptr, h_event

def obtem_handle_driver():
    return win32file.CreateFile(
        r"\\.\SentinelaDriver",
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
        None,
        win32file.OPEN_EXISTING,
        0,
        None
    )

def enviar_ioctl(ioctl_code, packet, pid, tamanho_buffer):
    global global_lock
    while True:
        with global_lock:
            try:
                sleep(0.05)
                # Tenta enviar o IOCTL_VERDICT (0x802)
                resposta = win32file.DeviceIoControl(globais.h_driver.handle, ioctl_code, packet, tamanho_buffer)
                return True, resposta
            except pywintypes.error as e:
                if e.winerror == ERROR_NOT_FOUND:
                    # O Driver já limpou o item (Timeout ou Cleanup)
                    print_log(f"[!] {text_interface["verdict_timetout"]} PID {pid}")
                    return False, None
                elif e.winerror == ERROR_INVALID_HANDLE:
                    # O contexto de memória no Driver sumiu ou o Magic Number falhou
                    print_log(f"[-] {text_interface["context_invalid"]} PID {pid}")
                    continue
                elif e.winerror == ERROR_INSUFFICIENT_BUFFER:
                    tamanho_buffer *= 2
                    print("novo tamanho do buffer:", tamanho_buffer)
                    continue
                elif e.winerror == ERROR_NO_MORE_FILES:
                    # Se o erro for 259 (No more entries), significa que outro worker
                    # foi mais rápido e a fila esvaziou. Volta a dormir.
                    # no more filesx
                    continue
                else:
                    # Outro erro real (ex: driver desconectado)
                    print_log(f"[-] {text_interface["critical_ioctl_error"]}: {str(e)}")
                    return False, None

def workload(worker_id, cd):
    global tempo_lock
    # tempo_inicio = -1
    # resposta = b""

    dump = BytesIO()
    tamanho_buffer = globais.buffer_size * 1024
    status, resposta = enviar_ioctl(0x222004, None, None, tamanho_buffer)
    if status:
        # guarda tempo de inicio do job
        tempo_inicio = time.time()
        if not resposta or len(resposta) < 18:
            print_log(f"[-] {text_interface["data_too_small"]}")
            return
        # data veio ok
    else:
        print("Erro na comunicação com o driver.")
        return

    # processa o job (Q (LONG LONG) = 8bytes e H (USHORT) = 2bytes
    # QQH tem 18bytes em x64
    pid, ctx_ptr, tamanho_filename = struct.unpack("QQH", resposta[:18])  # Pega os primeiros 18 bytes
    # le o filename usando o tamanho obtido em UTF-16
    inicio_dump = 18 + tamanho_filename
    path = resposta[18: inicio_dump].decode('utf-16')
    # tenta le o tamanho do dump (ULONG 4 bytes)
    try:
        tamanho_dump = struct.unpack("L", resposta[inicio_dump: inicio_dump + 4])[0]
    except struct.error:
        tamanho_dump = 0
    inicio_dump += 4
    # le o tamanho em bytes do dump
    if tamanho_dump > 0:
        dump.write(resposta[inicio_dump: inicio_dump + tamanho_dump])
        if worker_id: print_log(f"[Worker {worker_id}] Dump de memoria carregado do driver...")

    if worker_id: print_log(f"[Worker {worker_id}] {text_interface["new_job"]}: (pid {pid})")

    if path != "":
        # tenta converter nomes se necessario
        path = converte_nome_arquivos(path, worker_id)

        # verifica conexão com clamd, reconectando se necessario
        while True:
            try:
                if cd:
                    # checa conexão
                    res = cd.ping() # type: ignore
                    if res == "PONG":
                        if worker_id: print_log(f"[Worker {worker_id}] {text_interface["clamd_online"]}")
                        break
                    else:
                        if worker_id: print_log(f"[Worker {worker_id}] {text_interface["clamd_ping_failed"]}")
                        cd = None
                else:
                    # conecta ao clamd
                    cd = clamd_utils.conecta_clamd(worker_id)
                    if worker_id: print_log(f"[Worker {worker_id}] {text_interface["clamd_conneted"]}")
                    break
            except Exception as e:
                print_log(f"{text_interface["clamd_conect_error"]} ({str(e)}), {text_interface["reconecting"]}")
                if worker_id: print_log(f"[Worker {worker_id}] {text_interface["clamd_not_found"]}")
                cd = None
        if tamanho_dump == 0:
            # checando saude do arquivo
            safe, resultado = clamd_utils.checa_saude_arquivo(worker_id, path, cd, print_log)
        else:
            # checando o buffer recebido
            safe, resultado = clamd_utils.scaneia_dump(worker_id, dump, path, cd, print_log)
    else:
        # aceitando para nao causar erros mas ta errado isso ai
        if worker_id: print_log(f"[Worker {worker_id}] {text_interface["accept_and_continue"]}")
        print_log(text_interface["bug_empty_filename"])
        safe, resultado = True, text_interface["empty_path"]

    # montando pacote de veredito

    # ESTRUTURA DO PACOTE (Alinhamento de 8 bytes):
    # Q (unsigned long long) -> ProcessId (8 bytes)
    # Q (unsigned long long) -> PointerCtx (8 bytes)
    # ? booleano -> Verdict (1 byte)
    # 7x - 7 bytes de padding
    packet = struct.pack("QQ?7x", pid, ctx_ptr, safe)

    res = text_interface["tag_clean"] if safe else text_interface["tab_blocked"]
    if worker_id: print_log(f"[Worker {worker_id}] {text_interface["send_verdict"]}: {res}")

    tamanho_buffer = globais.buffer_size
    enviado, _resposta = enviar_ioctl(0x222008, packet, pid, tamanho_buffer)

    tempo_termino = time.time()
    tempo_decorrido = tempo_termino - tempo_inicio
    if not enviado:
        # enviando veredito para gui (timeout)
        if worker_id: print_log(f"{text_interface["warning"]}: Worker {worker_id} {text_interface["verdict_not_sended"]}")
        globais.verdict_queue.put((res, pid, f"[Worker {worker_id} ({tempo_decorrido:.2f}s)] {path}", "TIMEOUT"))
        print_log(f"[Worker {worker_id}] ({tempo_decorrido:.2f}s) Veredito não enviado por timeout PID: {pid}.")
    else:
        # enviando veredito para gui
        globais.verdict_queue.put((res, pid, f"[Worker {worker_id} ({tempo_decorrido:.2f}s)] {path}", resultado))
        print_log(f"[Worker {worker_id}] ({tempo_decorrido:.2f}s) {text_interface["job_end"]} PID: {pid}.")

    # atualiza global com tempo
    if tempo_decorrido > globais.maior_tempo:
        globais.maior_tempo = tempo_decorrido
    # atualiza media
    # utiliza lock
    with tempo_lock:
        if globais.media_tempo == 0:
            globais.media_tempo = tempo_decorrido
        else:
            globais.media_tempo = (globais.media_tempo + tempo_decorrido) / 2


def converte_nome_arquivos(path, _worker_id):
    caminho_windows = os.environ.get('SystemRoot')
    # tenta limpar string que pode ocasinalmente vir suja do kernel driver
    if path.startswith("\\Device"):
        print_log(f"{text_interface["converting_path"]}: {path}")
        path = drive_utils.device_path_to_dos_path(path)
    elif path.startswith("\\SystemRoot"):
        print_log(f"{text_interface["converting_path"]}: {path}")
        path = path.replace("\\SystemRoot", caminho_windows)
    elif path.startswith("\\??\\"):
        print_log(f"{text_interface["converting_path"]}: {path}")
        path = path[4:]
    return path

def inicia_workers(h_event):
    # Cria as threads passando o mesmo evento e o mesmo handle do device
    globais.workers = []
    escolhidos = []
    for w_id in range(globais.configuracao["num_workers"]):
        # escolhe um dos nomes pre configurados
        while True:
            tamanho = len(globais.configuracao["worker_names"])
            sorteio = random.randint(0, tamanho - 1)
            # print(f"tamanho: {tamanho} sorteio: {sorteio}")
            nome = globais.configuracao["worker_names"][sorteio]
            if nome not in escolhidos:
                escolhidos.append(nome)
                break
        worker = MeuWorker(h_event, f"{nome}_{w_id}")
        worker.start()
        globais.workers.append(worker)

# --- No encerramento do script (ex: Ctrl+C) ---
def shutdown_workers():
    print_log(f"[!] {text_interface["init_shutdown"]}")

    # sinaliza primeiro
    for t in globais.workers:
        t.stop()

    # aguarda a finalização de todos
    for t in globais.workers:
        t.join(timeout=2)

    print_log(f"--- {text_interface["pending_threads"]} ---")
    for thread in threading.enumerate():
        print_log(f"Thread {text_interface["still_alive"]}: {thread.name} - Daemon: {thread.daemon}")

    print_log(f"[!] {text_interface["stop_threads"]}")

def get_status_drv():
    # 8x4
    tamanho_esperado = 32
    if not globais.h_driver:
        return None
    data = win32file.DeviceIoControl(globais.h_driver.handle,0x222010, None, tamanho_esperado)
    if not data or len(data) < tamanho_esperado:
        print_log(f"[-] {text_interface["data_too_small"]}")
        return None
    cache_count, queue_count, active_threads, contador_timeouts, max_threads, max_cache_size, temp_timeout, failclose_enable = struct.unpack("LllllLl?3x", data[:tamanho_esperado])
    return  cache_count, queue_count, active_threads, contador_timeouts, max_threads, max_cache_size, temp_timeout, failclose_enable

def set_config_drv(queue_max_threshold, cache_max_entries, tempo_timeout, fail_close):
    # constroi o pacote de configuracao
    packet = struct.pack("lLl?3x", queue_max_threshold, cache_max_entries, tempo_timeout, fail_close)
    if not globais.h_driver:
        return False
    tamanho_buffer = globais.buffer_size
    status, _resposta = enviar_ioctl(0x222014, packet, None, tamanho_buffer)
    return status

def get_dump_from_pid(pid, dllname=""):
    if dllname == "":
        packet = struct.pack("Ql", pid, 0)
    else:
        packet = struct.pack("Ql", pid. len(dllname)) + dllname.encode("utf-16") + b"\0"

    if not globais.h_driver:
        return None
    tamanho_inicial_buffer = globais.buffer_size * 1024
    status, resposta = enviar_ioctl(0x222018, packet, None, tamanho_inicial_buffer)
    pid, dump_size = struct.unpack("QL4x", resposta[:16])

    return status, dump_size, resposta[16: 16 + dump_size]
