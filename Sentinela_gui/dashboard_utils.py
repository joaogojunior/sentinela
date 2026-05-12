import os
import datetime
from time import sleep
import threading
from PIL import Image
import pywintypes

from PyQt6.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem,
                             QVBoxLayout, QWidget, QPushButton, QLabel, QHeaderView,
                             QFileDialog, QHBoxLayout, QCheckBox, QMessageBox, QSizePolicy,
                             QAbstractItemView, QLineEdit, QComboBox, QFrame, QProgressDialog)
from PyQt6.QtCore import pyqtSignal, QObject, Qt, QTimer, QSharedMemory, QMetaObject

from PyQt6.QtGui import QIcon

import pystray

import clamd_utils
import globais
import process_utils

from criador_json import criador_json

try:
    import win32file
    import win32event
except ImportError:
    from win32 import win32file, win32event

from worker_utils import (encerrar_comunicacao, registra_monitor, obtem_handle_driver, shutdown_workers, inicia_workers,
                          print_log, get_status_drv, set_config_drv, get_dump_from_pid)

from lang_utils import text_interface_dict
text_interface = text_interface_dict[globais.configuracao["default_lang"]]

from pyinstaller_build_date import data_hora_build
from pyinstaller_utils import resource_path

# import sys
#
# def trace_threads(self, *args, **kwargs):
#     # Captura quem chamou a criação da thread
#     caller = sys._getframe(1).f_code.co_filename
#     line = sys._getframe(1).f_lineno
#     print(f"!!! Thread sendo criada por: {caller} na linha {line}")
#     return threading.Thread.__init__orig(self, *args, **kwargs)
#
# # Faz o "monkey patch" para rastrear
# threading.Thread.__init__orig = threading.Thread.__init__
# threading.Thread.__init__ = trace_threads

class WorkerSignals(QObject):
    log_event = pyqtSignal(str, str, str, str)
    show_window_requested = pyqtSignal()
    # atualiza_db = pyqtSignal()
    fim_atualizacao_db = pyqtSignal()
    update_pd = pyqtSignal(int)
    finished_pd = pyqtSignal()

class SentinelWorker(threading.Thread):
    def __init__(self, signals):
        super().__init__(name="thread-sentinel-worker")
        self.signals = signals
        self.running = True

    def open_driver(self):
        while self.running:
            try:
                globais.h_driver = obtem_handle_driver()
                self.signals.log_event.emit(text_interface["tag_driver"], "-", text_interface["driver_found"], "OK")
                return globais.h_driver
            except pywintypes.error as e:
                self.signals.log_event.emit(text_interface["tag_driver"], "-", f"{text_interface["error"]}: {e.winerror} - {e.strerror}", text_interface["tag_error"])
                self.signals.log_event.emit(text_interface["tag_driver"], "-", text_interface["driver_not_found"],
                                            text_interface["tag_error"])
                # espera 30 seg para tentar conectar ao dispositivo do driver novamente
                sleep(30)
        return None

    def startup_tasks(self):
        caminho_windows = os.environ.get('SystemRoot')
        # escaneia manualmente alguns arquivos que nao poderao ser checados pelo driver
        if globais.configuracao["debug"]:
            print_log(text_interface["debug_startup_file_check"])
        # atualiza logo ao iniciar
        # self.signals.atualiza_db.emit()
        cd = clamd_utils.conecta_clamd("startup")
        self.signals.log_event.emit("CLAMD", "", clamd_utils.get_clamd_ver(cd), text_interface["tag_ok"])

        self.signals.log_event.emit(text_interface["tag_system"], "-", text_interface["startup_file_check"], text_interface["tag_ok"])
        i = 0
        for arquivo in globais.startup_scan_list:
            i += 1
            self.signals.update_pd.emit(i)
            caminho_completo = os.path.join(str(caminho_windows), "system32", arquivo)
            sucesso, saida = clamd_utils.checa_saude_arquivo("startup", caminho_completo, cd, print_log)
            if sucesso:
                self.signals.log_event.emit(text_interface["tag_clean"], "-", f"{text_interface["scanning"]}: {caminho_completo}.", saida)
            elif globais.configuracao["debug"]:
                print_log(f"CLAMDSCAN {text_interface["virus_found"]}: {caminho_completo}.")
                print_log(f"CLAMDSCAN {text_interface["output"]}: {saida}")
                return False
        # sinaliza fim da carga
        self.signals.finished_pd.emit()

        self.signals.log_event.emit(text_interface["tag_system"], "-", text_interface["startup_check_finished"], text_interface["tag_ok"])
        if globais.configuracao["debug"]:
            print_log(text_interface["debug_check_ends"])
        return True

    def run(self):
        my_pid = os.getpid()
        if globais.configuracao["debug"]:
            print_log(f"{text_interface["my"]} pid: {my_pid}")
        self.signals.log_event.emit("MONITOR", "-", text_interface["my"] + " Pid: " + str(my_pid), text_interface["tag_ok"])

        while self.running and globais.clamd_pid == 0:
            if globais.configuracao["debug"]:
                print_log(text_interface["init_checking_service"])
            self.signals.log_event.emit(text_interface["tag_system"], "-", text_interface["checking_service"], "...")
            if clamd_utils.testa_servico_clamd_rodando():
                globais.clamd_pid = process_utils.obter_proc('clamd.exe')[1]
            else:
                if globais.configuracao["debug"]:
                    print_log(text_interface["init_service_not_running"])
                self.signals.log_event.emit("CLAMD", "-", text_interface["service_not_running"], text_interface["tag_error"])
                sleep(30)
        if not self.running:
            return

        if globais.configuracao["debug"]:
            print_log(f"Clamd pid: {globais.clamd_pid}")

        self.signals.log_event.emit(text_interface["tag_system"], "-", text_interface["service_online"] + " Pid: " + str(globais.clamd_pid), text_interface["tag_ok"])

        # executa "autoexec"
        if not self.startup_tasks():
            Dashboard.msgbox_html(text_interface["compromised_text"], text_interface["compromised_title"], QMessageBox.Icon.Critical)
            if globais.configuracao["debug"]:
                print_log(text_interface["compromised_msg"])
            self.signals.exit_requested.emit()

        # tenta abrir o driver (fica em loop tentando se conectar ao driver)
        h_driver = self.open_driver()
        # se driver for None significa que o app esta desligando
        if h_driver is None:
            return
        # registrando driver
        h_driver_ptr, h_event = registra_monitor(h_driver, my_pid, globais.clamd_pid)
        self.signals.log_event.emit("DRIVER", "-", f"{text_interface["reg_monitor_msg"]} PID {my_pid}", text_interface["tag_ok"])

        self.signals.log_event.emit("WORKERS", "-", f"{text_interface["sentinela_starting"]}: {globais.configuracao["num_workers"]}", text_interface["tag_ok"])

        # Inicializa os Workers
        inicia_workers(h_event)

        if globais.configuracao["debug"]:
            print_log(f"{text_interface["sentinela_starting"]}: {globais.configuracao["num_workers"]}")

        try:
            while self.running:
                # loop principal da gui
                # espera resultados das workers
                res, pid, path, resultado = globais.verdict_queue.get()
                # resultado recebido, mostrar na interface
                if not (pid == -1 and resultado == "finalize, por favor."):
                    self.signals.log_event.emit(res, str(pid), path, resultado)
        except Exception as e:
            self.signals.log_event.emit(text_interface["tag_error"], "-", str(e), text_interface["tag_error"])
        finally:
            if globais.configuracao["debug"]:
                print_log(text_interface["driver_thread_ends"])


def toggle_scan_nao_assinados():
    globais.configuracao_alterada = True
    globais.configuracao["scan_all"] = not globais.configuracao["scan_all"]


def toggle_logging():
    globais.configuracao_alterada = True
    globais.configuracao["logging"] = not globais.configuracao["logging"]


class Dashboard(QMainWindow):
    lbl_path: QLabel
    lbl_status: QLabel
    checkbox_scan_nao_assinados: QCheckBox
    checkbox_logging: QCheckBox
    table: QTableWidget
    btn_update: QPushButton
    tray: "pystray.Icon"
    t_tray: "threading.Thread"
    shared_memory: QSharedMemory
    timer: QTimer
    last_update_status: bool
    pd: QProgressDialog

    def __init__(self):
        super().__init__()
        self.janela_drv_config = None
        self.setWindowIcon(QIcon(resource_path('sentinela_gui.ico')))
        self.horario_proxima_atualizacao = self.calcular_hora_proxima_atualizacao().hour
        self.update_title()
        self.resize(900, 550)
        self.real_exit = False  # Controla se deve fechar de verdade

        self.setup_ui()

        # setup dos signals
        self.signals = WorkerSignals()
        self.signals.log_event.connect(self.add_log)
        self.signals.show_window_requested.connect(self.show_window_real)
        self.signals.fim_atualizacao_db.connect(self.fim_atualizacao_update)
        self.signals.update_pd.connect(self.update_progress_pd)
        self.signals.finished_pd.connect(self.on_finished_pd)

        self.worker = SentinelWorker(self.signals)

        # inicia a thread que se comunica com o driver
        self.worker.start()

        # setup icone da bandeja
        self.setup_pystray()

        # setup timer
        self.timer = QTimer(self)
        self.iniciar_timer_sincronizado()

        # timer do titlebar (atualiza a cada 30s)
        self.title_timer = QTimer(self)
        self.title_timer.timeout.connect(self.update_title)
        self.title_timer.start(30000)

    def update_title(self):
        self.setWindowTitle(f"Sentinela Zero-Trust {globais.versao_atual} | tempo medio: {globais.media_tempo:.2f}s. | tempo maximo: {globais.maior_tempo:.2f}s."  )

    @staticmethod
    def inicia_se_for_a_primeira():
        ja_rodando, versao, shared_memory = Dashboard.checa_gui_ja_rodando()
        if not ja_rodando and shared_memory:
            instancia = Dashboard()
            instancia.shared_memory = shared_memory
            return instancia
        else:
            Dashboard.msgbox_html(f"{text_interface["popup_msg"]} {versao}", text_interface["popup_title"], QMessageBox.Icon.Warning)
            if globais.configuracao["debug"]:
                print(text_interface["another_instance_running"])
            return None

    @staticmethod
    def msgbox_html(texto, titulo=text_interface["default_title"], icone=QMessageBox.Icon.Information):
        # Criar a caixa de mensagem
        msg = QMessageBox(icone, titulo, texto)

        # adiciona icone
        msg.setWindowIcon(QIcon(resource_path("sentinela_gui.ico")))

        # Exibir a janela
        msg.exec()

    @staticmethod
    def checa_gui_ja_rodando():
        retorno = True
        versao_reportada = ""
        shared_memory = QSharedMemory("versao")
        # Tenta se conectar à memória da primeira instância
        if not shared_memory.attach():
            # SOU A PRIMEIRA INSTÂNCIA
            if globais.configuracao["debug"]:
                print(text_interface["shared_mem_startup"], globais.versao_atual)
            retorno = False
            # 1. Cria espaço suficiente (tamanho de dados + 2)
            dados = globais.versao_atual.encode('utf-8')
            if shared_memory.create(len(dados) + 2):
                shared_memory.lock()
                # 2. Grava a string de versão na memória
                ptr = shared_memory.data()
                ptr[:len(dados)] = dados
                shared_memory.unlock()
        else:
            # SOU A SEGUNDA INSTÂNCIA
            shared_memory.lock()
            # Lê os dados
            tamanho = shared_memory.size()
            dados_bytes = shared_memory.data().asstring(tamanho)
            versao_reportada = dados_bytes.decode('utf-8').strip('\x00')
            shared_memory.unlock()
            shared_memory = None
        return retorno, versao_reportada, shared_memory

    def setup_pystray(self):
        # setup pystray
        # img = Image.new('RGB', (64, 64), (39, 174, 96))
        img = Image.open(resource_path("sentinela_gui.ico"))
        menu = pystray.Menu(
            pystray.MenuItem("🛡️ " + text_interface["open_dashboard"], self.show_window),
            pystray.MenuItem("❌" + text_interface["quit_menu"], self.tray_quit_app)
        )
        self.tray = pystray.Icon("Sentinela", img, "Sentinela Zero-Trust", menu)
        self.t_tray = threading.Thread(target=self.tray.run, name="thread-pystray")
        self.t_tray.start()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Configuração do Caminho do ClamAV
        path_layout = QHBoxLayout()
        self.lbl_path = QLabel(f"{text_interface["clamav_path"]}: {globais.configuracao["clamav_path"]}")
        btn_browse = QPushButton("📂")
        btn_browse.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn_browse.setToolTip(text_interface["change_clamav_folder"])
        btn_status = QPushButton("📍")
        btn_status.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn_status.setToolTip(text_interface["status"])
        btn_drv_config = QPushButton("🛠")
        btn_drv_config.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn_drv_config.setToolTip("Configurações")
        btn_clear = QPushButton("🧹")
        btn_clear.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn_clear.setToolTip("Limpas as mensagens")
        btn_about = QPushButton("⚠")
        btn_about.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        btn_about.setToolTip(text_interface["about"])
        btn_browse.clicked.connect(self.select_clamav_path)
        btn_status.clicked.connect(self.get_sentinela_status)
        btn_drv_config.clicked.connect(self.open_drv_config)
        btn_clear.clicked.connect(lambda: self.table.setRowCount(0))
        btn_about.clicked.connect(self.exibir_sobre)
        path_layout.addWidget(self.lbl_path)
        path_layout.addWidget(btn_browse)
        path_layout.addWidget(btn_status)
        path_layout.addWidget(btn_drv_config)
        path_layout.addWidget(btn_clear)
        path_layout.addWidget(btn_about)
        layout.addLayout(path_layout)

        linha_layout = QHBoxLayout()
        self.lbl_status = QLabel(f"CLAMD: {text_interface["clamd_conecting"]}...")
        self.lbl_status.setStyleSheet("font-weight: bold; color: #2980b9;")
        linha_layout.addWidget(self.lbl_status)
        linha_layout.addStretch()
        # Cria o Checkbox arquivos oficiais
        self.checkbox_scan_nao_assinados = QCheckBox(text_interface["official_bypass"])
        self.checkbox_scan_nao_assinados.setChecked(not globais.configuracao["scan_all"])
        # 3. Conecta o sinal stateChanged a uma função
        self.checkbox_scan_nao_assinados.stateChanged.connect(toggle_scan_nao_assinados)
        linha_layout.addWidget(self.checkbox_scan_nao_assinados)

        layout.addLayout(linha_layout)
        # Force a largura para zero via CSS. Isso remove os números e o espaço físico.

        self.table = QTableWidget(0, 5)
        self.table.setWordWrap(False)
        # self.table.resizeRowsToContents()
        # self.table.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.table.setStyleSheet("QHeaderView::section:vertical { width: 0px; border: none; }")
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setHorizontalHeaderLabels([text_interface["hheader_label_datetime"],
                                              text_interface["hheader_label_status"],
                                              text_interface["hheader_label_pid"],
                                              text_interface["hheader_label_file"],
                                              text_interface["hheader_label_details"]])
        hheader = self.table.horizontalHeader()
        # faz o campo arquivo mais largo
        if hheader:
            # Ajusta as colunas 1, 2, 3 e 5 (índices 0, 1, 2 e 4)
            hheader.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
            hheader.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            hheader.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            hheader.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            hheader.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        layout.addWidget(self.table)

        self.btn_update = QPushButton(text_interface["database_update"])
        self.btn_update.setMinimumHeight(40)
        self.btn_update.clicked.connect(self.botao_atualizar_cliclado)
        layout.addWidget(self.btn_update)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # 2. cria uma barra de progresso em um dialogo que bloqueia a UI
        self.pd = QProgressDialog("Executando comandos...", "Cancelar", 0, len(globais.startup_scan_list), self)
        self.pd.setWindowModality(Qt.WindowModality.WindowModal) # Bloqueia a janela pai
        self.pd.setMinimumDuration(0)             # Aparece instantaneamente
        self.pd.setValue(0)

    def update_progress_pd(self, val):
        self.pd.setValue(val)

    def on_finished_pd(self):
        self.pd.close()

    def open_drv_config(self):
        # Verifica se a janela já existe, se não, cria
        if self.janela_drv_config is None:
            self.janela_drv_config = JanelaConfig()
        self.janela_drv_config.show()
        self.janela_drv_config.raise_()           # Traz para o topo da pilha de janelas
        self.janela_drv_config.activateWindow()

    @staticmethod
    def exibir_sobre():
        link_html = (f'Sentinela Zero-Trust {globais.versao_atual} {text_interface["released_in"]} {data_hora_build}<p>'
                     f'<a href="https://github.com/joaogojunior" style="color: #0000ff;">'
                     f'{text_interface["visit_github"]}</a><p>'
                     # f'{text_interface["by"]}: João Guilherme &lt;joaogojunior@gmail.com&gt; '
                     f'<p>{text_interface["translated_by"]}: {text_interface["translator"]} &lt;'
                     f'{text_interface["translator_email"]}&gt;')
        # Exibir a janela
        Dashboard.msgbox_html(link_html, text_interface["about_msg"])

    def get_sentinela_status(self):
        resposta = get_status_drv()
        if resposta:
            cache_count, queue_count, active_threads, contador_timeouts, max_threads, max_cache_size, tempo_timeout, failclose_enable = resposta
            self.add_log("DRIVER", "", f"cache_count: {cache_count} - queue_count: {queue_count} - active_threads: {active_threads} - contador_timeouts: {contador_timeouts}", text_interface["tag_ok"])
            self.add_log("DRIVER", "", f"max_cache_size: {max_cache_size} - max_threads: {max_threads} - tempo_timeout: {tempo_timeout} - failclose_enable: {failclose_enable}", text_interface["tag_ok"])
        else:
            self.add_log("DRIVER", "", text_interface["driver_not_available"], text_interface["tag_error"])

    def select_clamav_path(self):
        dir_path = QFileDialog.getExistingDirectory(self, text_interface["select_clamav_folder"],
                                                    globais.configuracao["clamav_path"])
        if dir_path:
            globais.configuracao_alterada = True
            globais.configuracao["clamav_path"] = dir_path
            self.lbl_path.setText(f"{text_interface["clamav_path"]}: {globais.configuracao["clamav_path"]}")

    def reativa_botao_atualizar(self):
        self.btn_update.setText(text_interface["database_update"])
        self.btn_update.setEnabled(True)

    def botao_atualizar_cliclado(self):
        # desabilita o botao por 1h
        self.btn_update.setEnabled(False)
        self.run_freshclam()

    # sempre que atualizar desativa botao de atualizar por 1h
    def fim_atualizacao_update(self):
        # forca recarregar a db nova se atualizado
        clamd_utils.force_clamd_reload()

        # atualizar a versao no label
        ver = clamd_utils.get_clamd_ver()
        if globais.configuracao["debug"]:
            print_log(f"{text_interface["label_update"]}: {ver}")
        self.signals.log_event.emit("CLAMD", "", ver, "")

        if self.last_update_status:
            # desativa caso venha do update, se vier do botao ja vai estar desativado
            self.btn_update.setEnabled(False)
            # inicia timer de 1h
            self.btn_update.setText(text_interface["disabled_60min"])
            m_segundos = 60 * 60 * 1000
            QTimer.singleShot(m_segundos, self.reativa_botao_atualizar)
        else:
            self.reativa_botao_atualizar()
        # atualizar hora do proximo update
        self.atualiza_proximo_hora()

    def run_freshclam(self):
        def _task():
            self.signals.log_event.emit("FRESHCLAM", "-", f"Freshclam: {text_interface["start_up"]}", text_interface["tag_ok"])
            status, linhas = clamd_utils.run_freshclam()
            status2 = clamd_utils.run_fangfrisch()
            self.last_update_status = status and status2
            if self.last_update_status:
                self.signals.log_event.emit("FRESHCLAM", "-", text_interface["update_successful"], text_interface["tag_ok"])
                for linha in linhas:
                    self.signals.log_event.emit("FRESHCLAM", "-", linha, text_interface["tag_ok"])
                # self.status = "ATUALIZADO"
            else:
                self.signals.log_event.emit(
                    text_interface["tag_error"], "-", text_interface["update_not_successful"], text_interface["tag_error"])
                for linha in linhas:
                    self.signals.log_event.emit("FRESHCLAM", "-", linha, text_interface["tag_error"])
                # self.status = "ERRO AO ATUALIZAR"
            self.signals.fim_atualizacao_db.emit()

        threading.Thread(target=_task, daemon=True, name="thread-freshclam").start()

    def add_log(self, status, pid, path, detail):
        # 1. Atualiza o status na barra superior se for evento de sistema
        if status == "CLAMD":
            self.lbl_status.setText(f"Clamd: {path}")
            return

        # 2. Desabilita atualizações visuais temporariamente (Evita "flicker" e travamentos)
        self.table.setUpdatesEnabled(False)

        try:
            row = self.table.rowCount()
            self.table.insertRow(row)
            agora = datetime.datetime.now()
            items = [agora.strftime("%d/%m/%Y %H:%M:%S"), status, pid, path, detail]
            for i, text in enumerate(items):
                item_widget = QTableWidgetItem(str(text))
                if i in [1, 2, 4]:
                    item_widget.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                elif i == 3:
                    item_widget.setToolTip(path)

                # Cores de destaque para bloqueios
                if status == text_interface["tab_blocked"]:
                    item_widget.setBackground(Qt.GlobalColor.red)
                    item_widget.setForeground(Qt.GlobalColor.white)
                    # manda notificacao pro tray
                    self.tray.notify(text_interface["block_virus_success"], text_interface["sentinela_active"])
                elif status == text_interface["tag_clean"]:
                    item_widget.setForeground(Qt.GlobalColor.darkGreen)

                self.table.setItem(row, i, item_widget)

            # 3. Faz o scroll apenas se a janela estiver visível para economizar CPU
            if self.isVisible():
                self.table.scrollToBottom()

        finally:
            # 4. Reabilita o desenho da tabela após a inserção em lote
            self.table.setUpdatesEnabled(True)

    # FUNCIONALIDADE DE MINIMIZAR PARA TRAY
    def closeEvent(self, event):
        if self.real_exit:
            self.final_cleanup_and_exit()
            event.accept()
            app = QApplication.instance()
            if app:
                app.quit()
        else:
            event.ignore()
            self.hide()
            if hasattr(self, "janela_drv_config"):
                self.janela_drv_config.hide()
            if hasattr(self, 'tray'):
                self.tray.notify(text_interface["sentinela_background"], text_interface["sentinela_active"])

    def show_window(self):
        # Chama o sinal para que a THREAD PRINCIPAL execute o show
        self.signals.show_window_requested.emit()

    def show_window_real(self):
        self.show()
        self.setWindowState(Qt.WindowState.WindowActive)
        self.activateWindow()
        self.raise_()
        # Força o Windows a processar o desenho imediatamente
        QApplication.processEvents()

    def tray_quit_app(self):
        # Avisa a janela para aceitar o CloseEvent
        self.real_exit = True

        # dispara o closeEvent
        # Use o invokeMethod para garantir que o close ocorra na thread da GUI
        QMetaObject.invokeMethod(self, "close", Qt.ConnectionType.QueuedConnection)


    def final_cleanup_and_exit(self):
        if globais.configuracao["debug"]:
            print(text_interface["start_shutdown"])

        # 1. Garante que o tray pare e espera a thread dele morrer
        if hasattr(self, 'tray'):
            self.tray.stop()  # Reforça o stop

        if hasattr(self, 't_tray') and self.t_tray.is_alive():
            if globais.configuracao["debug"]:
                print(text_interface["waiting_stop_tray"])
            self.t_tray.join(timeout=2)

        if globais.configuracao["debug"]:
            print(text_interface["debug_stop_tray"])
        # SÓ AGORA, se quiser, limpe as referências
        self.tray = None

        if globais.configuracao_alterada:
            if globais.configuracao["debug"]:
                print(text_interface["config_save"])
            # salvando configuraao
            criador_json.escreve_json_padrao(globais.arquivo_configuracao, globais.configuracao)

        # 1. Para o loop da thread do driver (thread-sentinel-worker)
        if hasattr(self, 'worker'):
            self.worker.running = False
        # envia mensagem terminal...
        globais.verdict_queue.put((True, -1, "", "finalize, por favor."))

        if globais.configuracao["debug"]:
            print(text_interface["debug_stop_workers"])
        # para os workers
        shutdown_workers()

        if globais.configuracao["debug"]:
            print(text_interface["debug_driver_closing"])
        encerrar_comunicacao()

    @staticmethod
    def calcular_hora_proxima_atualizacao():
        # primeiro calcula o horario da proxima atualizacao
        agora = datetime.datetime.now()
        # inicializa atributo com a hora da proxima_atualizacao
        # Calcula a próxima janela de 6h (00, 06, 12, 18)
        proxima_hora_timer = (((agora.hour // int(globais.configuracao["update_interval"])) + 1) *
                              int(globais.configuracao["update_interval"]))

        # calcula o datetime ho horario obtido
        if proxima_hora_timer == 24:
            # faz uma copia alterada de agora com o timestamp da 0h do novo dia
            proxima_datetime = (agora.replace(hour=0, minute=0, second=0, microsecond=0) +
                                datetime.timedelta(days=1))
        else:
            # faz uma copia alterada de agora com o timestamp da horario obtido
            proxima_datetime = agora.replace(hour=proxima_hora_timer, minute=0, second=0, microsecond=0)

        # # salva nova proxima hora em horaio_proxima_atualizacao
        # self.horario_proxima_atualizacao = proxima_hora_timer
        return proxima_datetime

    def calcular_ms_ate_proxima_atualizacao(self):
        # calcula diferenca de tempo em ms
        ms_espera = int((self.calcular_hora_proxima_atualizacao() - datetime.datetime.now()).total_seconds() * 1000)
        self.signals.log_event.emit(text_interface["tag_system"], "-",
                                    f"{text_interface["time_next_update"]}: %dh" % self.horario_proxima_atualizacao, text_interface["tag_ok"])
        if globais.configuracao["debug"]:
            print(text_interface["next_update"], self.horario_proxima_atualizacao, ms_espera)
        return ms_espera

    def iniciar_timer_sincronizado(self):
        ms_espera = self.calcular_ms_ate_proxima_atualizacao()
        if globais.configuracao["debug"]:
            print(text_interface["starting_singleshot_timer"])
        # Primeiro disparo no horário exato
        QTimer.singleShot(ms_espera, self.timer_ciclico)

    def timer_ciclico(self):
        if globais.configuracao["debug"]:
            print(text_interface["starting_timer"])
        # primeira atualizacao agendada
        self.inicia_atualizacao_agendada()
        # as outras acontecerao no intervalo configurado (padrao 6h)
        ms_espera = int(globais.configuracao["update_interval"]) * 60 * 60 * 1000
        self.timer.timeout.connect(self.inicia_atualizacao_agendada)
        self.timer.start(ms_espera)

    def atualiza_proximo_hora(self):
        # checa se eh necessario atualizar a hora da checagem
        hora_proxima_atualizacao_calculada = self.calcular_hora_proxima_atualizacao()
        if self.horario_proxima_atualizacao == hora_proxima_atualizacao_calculada.hour:
            if globais.configuracao["debug"]:
                print(text_interface["already_updated"])
            return
        self.horario_proxima_atualizacao = hora_proxima_atualizacao_calculada.hour
        if globais.configuracao["debug"]:
            print(text_interface["update_next_time"], self.horario_proxima_atualizacao)
        self.signals.log_event.emit(text_interface["tag_system"], "-",
                                    f"{text_interface["time_next_update"]}: %dh" % self.horario_proxima_atualizacao,
                                    text_interface["tag_ok"])

    def inicia_atualizacao_agendada(self):
        if globais.configuracao["debug"]:
            print(text_interface["sched_update"])
        self.run_freshclam()

class JanelaConfig(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Editar configuracoes do driver")
        self.setFixedWidth(300)
        self.setWindowIcon(QIcon(resource_path('sentinela_gui.ico')))

        layout = QVBoxLayout()
        layout.setSpacing(5)  # Espaçamento apertado entre elementos
        layout.setContentsMargins(10, 10, 10, 10)
        # 2. Cria o Checkbox com o texto
        self.checkbox_logging = QCheckBox(text_interface["log_enable"])
        # Opcional: Iniciar o checkbox marcado
        self.checkbox_logging.setChecked(globais.configuracao["logging"])
        # 3. Conecta o sinal stateChanged a uma função
        self.checkbox_logging.stateChanged.connect(toggle_logging)
        layout.addWidget(self.checkbox_logging)

        status_drv = get_status_drv()
        if status_drv is not None:
            # --- ADICIONE ESTE BLOCO AQUI (O SEPARADOR) ---
            separador = QFrame()
            separador.setFrameShape(QFrame.Shape.HLine)  # Linha Horizontal
            separador.setFrameShadow(QFrame.Shadow.Sunken)  # Efeito de linha "fundida" no fundo
            separador.setStyleSheet("color: #cccccc; margin: 10px 0px;")  # Cor cinza e margem superior/inferior
            layout.addWidget(separador)

            # 1. Criando os 4 TextEdits
            self.text_edits = []
            self.labels = ["max_threads", "max_cache_size", "tempo_timeout"]

            textos = status_drv[4:7]
            # textos = ["bla", "ble", "bli"]
            for i in range(3):
                la = QLabel()
                la.setStyleSheet("font-weight: bold;")
                la.setText(self.labels[i])
                te = QLineEdit() # Linha única
                te.setText(str(textos[i]))
                te.setFixedHeight(25) # Altura reduzida
                layout.addWidget(la)
                layout.addWidget(te)
                self.text_edits.append(te)
            self.check_box = QCheckBox("failclose enable")
            self.check_box.setChecked(status_drv[-1])
            # self.check_box.setChecked(True)
            layout.addWidget(self.check_box)

            # 3. Criando o Botão
            self.botao = QPushButton("💾Atualiza configuração")
            self.botao.clicked.connect(self.envia_config)
            layout.addWidget(self.botao)

            # --- ADICIONE ESTE BLOCO AQUI (O SEPARADOR) ---
            separador2 = QFrame()
            separador2.setFrameShape(QFrame.Shape.HLine)  # Linha Horizontal
            separador2.setFrameShadow(QFrame.Shadow.Sunken)  # Efeito de linha "fundida" no fundo
            separador2.setStyleSheet("color: #cccccc; margin: 10px 0px;")  # Cor cinza e margem superior/inferior
            layout.addWidget(separador2)

            # 2. Criando o Dropdown (ComboBox)
            self.combo = QComboBox()
            # self.combo.addItems(["blo", "blu"])
            layout.addWidget(self.combo)
            la = QLabel("🔎Filtrar por nome")
            self.qline_edit = QLineEdit()
            self.qline_edit.editingFinished.connect(self.filtra_lista)
            layout.addWidget(la)
            layout.addWidget(self.qline_edit)
            # 3. Criando o Botão
            self.botao_dump = QPushButton("👻Dump do processo")
            self.botao_dump.clicked.connect(self.inicia_dump)
            layout.addWidget(self.botao_dump)
            # inicializa o combobox
            self.filtra_lista()

        # Aplicar layout
        self.setLayout(layout)

    def carrega_combo(self, lista_processos):
        for dic in lista_processos:
            nome = dic["name"]
            pid = dic["pid"]
            self.combo.addItem(f"{pid} - {nome}")

    def filtra_lista(self):
        selecao = self.qline_edit.text().split(":")[0]
        self.combo.clear()
        lista_filtrada = process_utils.obter_list_proc_por_nome(selecao)
        self.carrega_combo(lista_filtrada)

    def envia_config(self):
        queue_max_threshold = int(self.text_edits[0].text())
        cache_max_entries = int(self.text_edits[1].text())
        tempo_timeout = int(self.text_edits[2].text())
        fail_close = self.check_box.isChecked()
        print(f"Enviando a seguinte configuração para o driver: {queue_max_threshold, cache_max_entries, tempo_timeout, fail_close}")
        resposta = set_config_drv(queue_max_threshold, cache_max_entries, tempo_timeout, fail_close)
        if resposta:
            Dashboard.msgbox_html("Dados enviados com sucesso!", "Salvando configuração")
        else:
            Dashboard.msgbox_html("Dados não foram salvos :(", "Salvando configuração", QMessageBox.Icon.Critical)

    def inicia_dump(self):
        selecao = self.combo.currentText()
        pid, nome = selecao.split(" - ")
        dllname = ""
        try:
            dllname = self.qline_edit.text().split(":")[1]
        except IndexError as e:
            pass
        sucesso, dump_size, dump = get_dump_from_pid(int(pid))
        if sucesso:
            try:
                with open("dumped_" + nome, "bw") as arquivo:
                    arquivo.write(dump)
                    Dashboard.msgbox_html(f"Dump salvo com sucesso!\nArquivo: {"dumped_" + nome}\nTamanho: {dump_size}", "Mensagem do dump")
            except Exception as e:
                Dashboard.msgbox_html(f"Erro: Não foi possivel salvar o arquivo. ({str(e)})",
                                      "Mensagem do dump", QMessageBox.Icon.Critical)
        else:
            Dashboard.msgbox_html(f"Erro: Não foi possivel realizar o dump. (consulte logs do kernel)",
                                  "Mensagem do dump", QMessageBox.Icon.Critical)


