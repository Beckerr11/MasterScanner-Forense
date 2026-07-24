
import psutil
import ctypes
import sys
import os
import json

# Definir constantes para as APIs do Windows (para uso com ctypes)
# Estas constantes são para Windows e serão usadas quando o script for executado lá.
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_EXECUTE_READWRITE = 0x40

# Estruturas para VirtualQueryEx (Windows API)
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_ulong),
        ("Protect", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
    ]

def get_process_memory_regions(pid):
    """
    Obtém informações sobre as regiões de memória de um processo no Windows.
    Esta função é específica para Windows e requer ctypes.
    """
    if sys.platform != "win32":
        # print("[*] Esta função é apenas para Windows. Ignorando.")
        return []

    regions = []
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        process_handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)

        if not process_handle:
            # print(f"[!] Não foi possível abrir o processo {pid}. Erro: {ctypes.get_last_error()}")
            return []

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        while kernel32.VirtualQueryEx(process_handle, address, ctypes.byref(mbi), ctypes.sizeof(mbi)):
            regions.append({
                "BaseAddress": hex(mbi.BaseAddress),
                "RegionSize": mbi.RegionSize,
                "State": mbi.State,
                "Protect": mbi.Protect,
                "Type": mbi.Type,
                "AllocationBase": hex(mbi.AllocationBase),
                "AllocationProtect": mbi.AllocationProtect,
            })
            address += mbi.RegionSize
            if address == 0: # Evitar loop infinito se RegionSize for 0
                break

        kernel32.CloseHandle(process_handle)
    except Exception as e:
        print(f"[!] Erro ao obter regiões de memória para PID {pid}: {e}")
    return regions

def analyze_process_for_injection(process):
    """
    Analisa um processo em busca de indicadores de injeção de memória.
    """
    findings = []
    try:
        # 1. Verificar regiões de memória RWX sem backing de arquivo (Windows)
        if sys.platform == "win32":
            memory_regions = get_process_memory_regions(process.pid)
            for region in memory_regions:
                # PAGE_EXECUTE_READWRITE (0x40) e MEM_PRIVATE (0x20000) e MEM_COMMIT (0x1000)
                if region["Protect"] == PAGE_EXECUTE_READWRITE and region["Type"] == MEM_PRIVATE and region["State"] == MEM_COMMIT:
                    # Esta é uma simplificação. Em um scanner real, verificaríamos se a região
                    # tem um módulo associado ou se é uma região de heap legítima.
                    # Para este propósito, consideramos RWX + Private + Committed como suspeito.
                    findings.append({
                        "type": "RWX_Private_Memory",
                        "description": f"Região de memória RWX privada e comprometida sem backing aparente.",
                        "address": region["BaseAddress"],
                        "size": region["RegionSize"],
                        "details": region
                    })

        # 2. Verificar threads remotas (difícil de detectar genericamente sem APIs de debug ou drivers)
        # psutil.Process.threads() retorna threads do próprio processo. Detectar threads *injetadas*
        # de outro processo requer inspeção mais profunda (ex: WinAPI CreateRemoteThread, ou drivers).
        # Por enquanto, esta é uma placeholder para futuras implementações de kernel/driver.
        # print(f"[*] Placeholder: Verificando threads remotas para PID {process.pid}")

        # 3. Verificar hooks de API (requer acesso a memória do processo e análise de código)
        # print(f"[*] Placeholder: Verificando hooks de API para PID {process.pid}")

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass # Processo já terminou ou acesso negado, ignorar
    except Exception as e:
        print(f"[!] Erro ao analisar processo {process.pid} ({process.name()}): {e}")

    return findings

def main():
    print("[*] Iniciando Deep Memory Scanner...")
    print("[*] Plataforma detectada: ", sys.platform)

    all_findings = []

    for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
        try:
            process_info = {
                "pid": proc.info['pid'],
                "name": proc.info['name'],
                "exe": proc.info['exe'],
                "cmdline": proc.info['cmdline'],
            }
            print(f"[*] Analisando processo: {process_info['name']} (PID: {process_info['pid']})")
            
            findings = analyze_process_for_injection(proc)
            if findings:
                all_findings.append({
                    "process": process_info,
                    "detections": findings
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        except Exception as e:
            print(f"[!] Erro geral ao processar PID {proc.pid}: {e}")

    if all_findings:
        print("\n[+] DETECÇÕES DE INJEÇÃO/ALTERAÇÃO DE MEMÓRIA ENCONTRADAS:")
        print(json.dumps(all_findings, indent=4))
        with open("memory_scan_results.json", "w") as f:
            json.dump(all_findings, f, indent=4)
        print("[*] Resultados salvos em memory_scan_results.json")
    else:
        print("\n[-] Nenhuma detecção de injeção/alteração de memória encontrada.")

if __name__ == "__main__":
    main()
