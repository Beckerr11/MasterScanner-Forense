
import ctypes
import sys
import os

def dump_memory_region(pid, base_address, size, output_file):
    """
    Realiza o dump de uma região específica de memória de um processo.
    """
    if sys.platform != "win32":
        # print("[*] Esta função é apenas para Windows.")
        return False

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        process_handle = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)

        if not process_handle:
            print(f"[!] Erro ao abrir processo {pid} para dump: {ctypes.get_last_error()}")
            return False

        buffer = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t(0)

        if kernel32.ReadProcessMemory(process_handle, base_address, buffer, size, ctypes.byref(bytes_read)):
            with open(output_file, "wb") as f:
                f.write(buffer.raw)
            print(f"[+] Dump realizado com sucesso: {output_file} ({bytes_read.value} bytes)")
            kernel32.CloseHandle(process_handle)
            return True
        else:
            print(f"[!] Erro ao ler memória no endereço {hex(base_address)}: {ctypes.get_last_error()}")
            kernel32.CloseHandle(process_handle)
            return False

    except Exception as e:
        print(f"[!] Erro durante o dump de memória: {e}")
        return False

def check_kernel_drivers():
    """
    Verifica os drivers carregados no kernel em busca de anomalias (ex: drivers sem assinatura).
    No Windows, isso pode ser feito via EnumDeviceDrivers.
    """
    if sys.platform != "win32":
        # print("[*] Esta função é apenas para Windows.")
        return []

    drivers_info = []
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        # Obter endereços de base dos drivers
        drivers = (ctypes.c_void_p * 1024)()
        cb = ctypes.sizeof(drivers)
        needed = ctypes.c_ulong()

        if psapi.EnumDeviceDrivers(ctypes.byref(drivers), cb, ctypes.byref(needed)):
            count = int(needed.value / ctypes.sizeof(ctypes.c_void_p))
            for i in range(count):
                name_buffer = ctypes.create_unicode_buffer(1024)
                if psapi.GetDeviceDriverBaseNameW(drivers[i], name_buffer, ctypes.sizeof(name_buffer)):
                    drivers_info.append({
                        "BaseAddress": hex(drivers[i] or 0),
                        "Name": name_buffer.value
                    })
    except Exception as e:
        print(f"[!] Erro ao enumerar drivers de kernel: {e}")
    
    return drivers_info

if __name__ == "__main__":
    # Exemplo de uso (apenas no Windows)
    if sys.platform == "win32":
        print("[*] Verificando drivers de kernel...")
        drivers = check_kernel_drivers()
        for d in drivers:
            print(f"Driver: {d['Name']} em {d['BaseAddress']}")
