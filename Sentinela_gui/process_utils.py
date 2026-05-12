import psutil

def obter_proc(process_name):
    target_proc = None
    pid = 0
    # Procura pelo processo do clamd na lista do Windows
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'].lower() == process_name:
                target_proc = proc
                pid = proc.info['pid']
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return target_proc, pid

def obter_list_proc_por_nome(process_name):
    lista_processos = []
    # Procura pelo processo pelo nome parcial na lista do Windows
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if process_name.lower() in proc.info['name'].lower():
                lista_processos.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return lista_processos
