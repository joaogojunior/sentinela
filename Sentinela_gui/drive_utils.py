import win32api
import win32file


def device_path_to_dos_path(nt_path):
    # 1. Obtém todas as letras de unidade (ex: ['C:', 'D:'])
    drives = [d.rstrip('\\') for d in win32api.GetLogicalDriveStrings().split('\0') if d]

    for drive in drives:
        # 2. Mapeia a letra para o caminho do dispositivo (ex: \Device\HarddiskVolume3)
        try:
            device_name = win32file.QueryDosDevice(drive)
            # QueryDosDevice retorna uma string com múltiplos mapeamentos separados por \0
            target_device = device_name.split('\0')[0]

            # 3. Verifica se o caminho inicia com este dispositivo
            if nt_path.lower().startswith(target_device.lower()):
                return nt_path.replace(target_device, drive, 1)
        except Exception:
            continue

    return nt_path  # Retorna original se não encontrar mapeamento

