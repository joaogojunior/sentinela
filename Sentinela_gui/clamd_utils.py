import clamd
import socket
import subprocess
import os
import wintrust_utils
from time import sleep
import sys
from fangfrisch.__main__ import main as fangfrisch_main

import globais
from worker_utils import print_log
from lang_utils import text_interface_dict
text_interface = text_interface_dict[globais.configuracao["default_lang"]]


def testa_servico_clamd_rodando():
    try:
        # Cria um socket de teste rápido para verificar se o serviço está "vivo"
        with socket.create_connection(('127.0.0.1', 3310), timeout=30):
            return True
    except (socket.timeout, ConnectionRefusedError):
        return False

def conecta_clamd(worker_id=None):
    cd: clamd.ClamdNetworkSocket | None = None
    while cd is None:
        try:
            if testa_servico_clamd_rodando():
                cd = clamd.ClamdNetworkSocket(host='127.0.0.1', port=3310)
            else:
                if worker_id is not None:
                    print_log(f"[Worker {worker_id}] {text_interface["connection_deny_with_retry"]}")
        except clamd.ConnectionError:
            cd = None
            if worker_id is not None:
                print_log(f"[Worker {worker_id}] {text_interface["not_connected_with_retry"]}")
    return cd

def get_clamd_ver(cd=None):
    if not cd:
        cd = conecta_clamd()
    info = cd.version()
    return info

def force_clamd_reload(cd=None):
    if not cd:
        cd = conecta_clamd()
        cd.reload()
        sleep(5)
        # Loop de verificação para garantir que o serviço está pronto
        while cd.ping() != 'PONG':
            # O daemon pode não responder enquanto carrega a base
            if globais.configuracao["debug"]:
                print_log(f"{text_interface["waiting_db_load"]}...")
            sleep(2)
    return

def run_freshclam():
    path_fresh = os.path.join(globais.configuracao["clamav_path"], "freshclam.exe")
    if os.path.exists(path_fresh):
        res = subprocess.run(f'"{path_fresh}"', shell=True, capture_output=True)
        linhas = res.stdout.decode(globais.configuracao["default_codepage"]).split("\n")[:-1]
        if res.returncode == 0:
            return True, linhas
        else:
            return False, linhas
    return False, [f"freshclam.exe {text_interface["not_found"]}."]

def run_fangfrisch():
    if os.path.isfile("./fangfrisch.conf"):
        # Simula a passagem de argumentos do terminal para dentro do Python
        sys.argv = ['fangfrisch', '-c', './fangfrisch.conf', 'refresh']
        ret = fangfrisch_main()
        if ret == 0:
            return True
    return False

def checa_saude_arquivo(worker_id, caminho_arquivo, cd, logger):
    if not os.path.isfile(caminho_arquivo):
        safe = True
        resultado = text_interface["error_file_not_found"]
        return safe, resultado

    safe = False
    if worker_id is not None:
        logger(f"[Worker {worker_id}] {text_interface["checking_health"]}: {caminho_arquivo}")
    res = False
    msg = ""
    if not globais.configuracao["scan_all"]:
        # se a configuracao for false checa apenas os arquivos nao assinados ou nao oficiais
        # entao verifica se eh um arquivo oficial primeiro.
        res, msg = wintrust_utils.is_microsoft_signed(caminho_arquivo)
    if res:
        # se o wintrust executou e retornou True entra aqui
        if worker_id is not None:
            logger(f"[Worker {worker_id}] {msg}")
        safe = True
        resultado = f"{text_interface["certificate"]}: {text_interface["tag_ok"]}"
    else:
        # checa arquvo com clamd
        try:
            res = scan_ok(cd, caminho_arquivo)[caminho_arquivo]
            if res[0] == 'OK':
                if worker_id is not None:
                    logger(f"[Worker {worker_id}] {caminho_arquivo}: {text_interface["clamav_file_clean"]}")
                safe = True
                resultado = f"Clamav: {text_interface["tag_ok"]}"
            else:
                if worker_id is not None:
                    logger(f"[Worker {worker_id}] {caminho_arquivo}: clamav {text_interface["virus"]}: {res}")
                resultado = f"{text_interface["capitalized_virus"]}: " + res[1]
        except Exception as e:
            logger(f"{text_interface["error_checking_file"]} {caminho_arquivo}: ({str(e)})")
            if worker_id is not None:
                logger(f"[Worker {worker_id}: {text_interface["blocking_process"]} ({caminho_arquivo}), {text_interface["block_msg"]}")
            safe = False
            resultado = f"Clamav: {text_interface["error"]}"
    return safe, resultado

def scaneia_dump(worker_id, dump, caminho_arquivo, cd, logger):
    if worker_id is not None:
        logger(f"[Worker {worker_id}] {text_interface["checking_health"]}: {caminho_arquivo}")
    safe = False

    # checa arquvo com clamd
    try:
        res = cd.instream(dump)
        if res[0] == 'OK':
            if worker_id is not None:
                logger(f"[Worker {worker_id}] {caminho_arquivo}: {text_interface["clamav_file_clean"]}")
            safe = True
            resultado = f"Clamav: {text_interface["tag_ok"]}"
        else:
            if worker_id is not None:
                logger(f"[Worker {worker_id}] {caminho_arquivo}: clamav {text_interface["virus"]}: {res}")
            resultado = f"{text_interface["capitalized_virus"]}: " + res[1]
    except Exception as e:
        logger(f"{text_interface["error_checking_file"]} {caminho_arquivo}: ({str(e)})")
        if worker_id is not None:
            logger(f"[Worker {worker_id}: {text_interface["blocking_process"]} ({caminho_arquivo}), {text_interface["block_msg"]}")
        resultado = f"Clamav: {text_interface["error"]}"
    return safe, resultado

def scan_ok(cd, file):
    return _file_system_scan(cd, "SCAN", file)

def _file_system_scan(self, command, file):
    """
    "consertado" por joao guilherme: O problema que eu tive com essa funcao eh que
    ela criava um dicinario com uma chave com CASE diferente do nome fornecido o que
    nao era desejavel no meu user case.

    Scan a file or directory given by filename using multiple threads (faster on SMP machines).
    Do not stop on error or virus found.
    Scan with archive support enabled.

    file (string): filename or directory (MUST BE ABSOLUTE PATH !)

    return:
      - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}

    May raise:
      - ConnectionError: in case of communication problem
    """

    try:
        self._init_socket()
        self._send_command(command, file)

        dr = {}
        for result in self._recv_response_multiline().split('\n'):
            if result:
                _filename, reason, status = self._parse_response(result)
                dr[file] = (status, reason)

        return dr

    finally:
        self._close_socket()