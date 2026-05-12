import os
import sys

def resource_path(relative_path):
    """ Obtém o caminho absoluto para recursos, funciona para dev e para PyInstaller """
    try:
        # O PyInstaller cria uma pasta temporária e armazena o caminho em _MEIPASS
        base_path = sys._MEIPASS
        print(f"retornando caminho atual: {base_path}")
    except Exception as e:
        base_path = os.path.join(os.path.abspath("."), "Sentinela_gui", "img")
        print(f"retornando caminho atual ({e}): {base_path}")

    return os.path.join(base_path, relative_path)